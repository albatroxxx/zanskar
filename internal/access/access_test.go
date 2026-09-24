// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/store"
)

func setup(t *testing.T) (context.Context, *Repo) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	now := store.TimeArg(time.Now())
	ex := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, db.Rebind(q), args...); err != nil {
			t.Fatal(err)
		}
	}
	ex(`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1','alice','Alice',?,?)`, now, now)
	ex(`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u2','bob','Bob',?,?)`, now, now)
	ex(`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t1','web1','10.0.0.1','linux',?,?)`, now, now)
	return ctx, NewRepo(db)
}

func TestRequestLifecycle(t *testing.T) {
	ctx, r := setup(t)

	req := &Request{UserID: "u1", TargetID: "t1", Protocol: "ssh", Reason: "deploy", RequestedMinutes: 60}
	if err := r.Create(ctx, req); err != nil {
		t.Fatal(err)
	}
	if req.Status != StatusPending {
		t.Fatalf("new request should be pending, got %s", req.Status)
	}

	exp := time.Now().UTC().Add(time.Hour)
	got, err := r.Decide(ctx, req.ID, "u2", StatusApproved, "ok", &exp)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusApproved || got.ExpiresAt == nil || got.ApproverUserID != "u2" {
		t.Fatalf("bad approve: %+v", got)
	}
	if !got.Active(time.Now().UTC()) {
		t.Fatal("approved grant should be active")
	}

	// A second decision on a non-pending request is rejected.
	if _, err := r.Decide(ctx, req.ID, "u2", StatusApproved, "", &exp); !errors.Is(err, ErrState) {
		t.Fatalf("re-decide should be ErrState, got %v", err)
	}
	if act, err := r.ActiveForUser(ctx, "u1", time.Now().UTC()); err != nil || len(act) != 1 {
		t.Fatalf("active grants: len=%d err=%v", len(act), err)
	}

	// Revoke ends the grant.
	rv, err := r.Revoke(ctx, req.ID, "done")
	if err != nil {
		t.Fatal(err)
	}
	if rv.Status != StatusRevoked {
		t.Fatalf("want revoked, got %s", rv.Status)
	}
	if act, _ := r.ActiveForUser(ctx, "u1", time.Now().UTC()); len(act) != 0 {
		t.Fatal("no active grants after revoke")
	}
	if _, err := r.Get(ctx, "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing request should be ErrNotFound, got %v", err)
	}

	// Deny leaves no expiry.
	d := &Request{UserID: "u1", TargetID: "t1", Protocol: "ssh", Reason: "x", RequestedMinutes: 30}
	if err := r.Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	dd, err := r.Decide(ctx, d.ID, "u2", StatusDenied, "no", nil)
	if err != nil {
		t.Fatal(err)
	}
	if dd.Status != StatusDenied || dd.ExpiresAt != nil {
		t.Fatalf("bad deny: %+v", dd)
	}

	// Expiry sweep flips a lapsed grant to expired.
	e := &Request{UserID: "u1", TargetID: "t1", Protocol: "ssh", Reason: "y", RequestedMinutes: 1}
	if err := r.Create(ctx, e); err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().Add(-time.Minute)
	if _, err := r.Decide(ctx, e.ID, "u2", StatusApproved, "", &past); err != nil {
		t.Fatal(err)
	}
	if n, err := r.ExpireDue(ctx, time.Now().UTC()); err != nil || n < 1 {
		t.Fatalf("ExpireDue: n=%d err=%v", n, err)
	}
	if g, _ := r.Get(ctx, e.ID); g.Status != StatusExpired {
		t.Fatalf("lapsed grant should be expired, got %s", g.Status)
	}
}

func TestEligiblePolicy(t *testing.T) {
	ref := policy.TargetRef{ID: "t1", Tags: map[string]string{"env": "prod"}}
	approval := &policy.Policy{Enabled: true, RequireApproval: true, Selector: policy.Selector{Targets: []string{"t1"}}, Protocols: []string{"ssh"}}
	standing := &policy.Policy{Enabled: true, Selector: policy.Selector{Targets: []string{"t1"}}, Protocols: []string{"ssh"}}
	disabled := &policy.Policy{Enabled: false, RequireApproval: true, Selector: policy.Selector{Targets: []string{"t1"}}, Protocols: []string{"ssh"}}

	if eligiblePolicy([]*policy.Policy{standing}, ref, "ssh") != nil {
		t.Error("standing (non-approval) access is not requested through PIM")
	}
	if eligiblePolicy([]*policy.Policy{disabled}, ref, "ssh") != nil {
		t.Error("a disabled policy must not confer eligibility")
	}
	if eligiblePolicy([]*policy.Policy{approval}, ref, "rdp") != nil {
		t.Error("a protocol the policy does not grant must not match")
	}
	if eligiblePolicy([]*policy.Policy{standing, approval}, ref, "ssh") == nil {
		t.Error("an approval-gated policy should confer eligibility")
	}
}

func TestHasActiveGrant(t *testing.T) {
	ctx, r := setup(t)
	now := func() time.Time { return time.Now().UTC() }

	req := &Request{UserID: "u1", TargetID: "t1", Protocol: "ssh", Reason: "x", RequestedMinutes: 60}
	if err := r.Create(ctx, req); err != nil {
		t.Fatal(err)
	}
	if ok, _ := r.HasActiveGrant(ctx, "u1", "t1", "", "ssh", now()); ok {
		t.Fatal("a pending request is not an active grant")
	}
	exp := now().Add(time.Hour)
	if _, err := r.Decide(ctx, req.ID, "u2", StatusApproved, "", &exp); err != nil {
		t.Fatal(err)
	}
	if ok, err := r.HasActiveGrant(ctx, "u1", "t1", "", "ssh", now()); err != nil || !ok {
		t.Fatalf("approved grant should be active: ok=%v err=%v", ok, err)
	}
	for _, c := range []struct{ user, tgt, proto, why string }{
		{"u1", "t1", "rdp", "wrong protocol"},
		{"u1", "other", "ssh", "wrong target"},
		{"u2", "t1", "ssh", "wrong user"},
	} {
		if ok, _ := r.HasActiveGrant(ctx, c.user, c.tgt, "", c.proto, now()); ok {
			t.Errorf("%s should not match a grant", c.why)
		}
	}
	if _, err := r.Revoke(ctx, req.ID, "done"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := r.HasActiveGrant(ctx, "u1", "t1", "", "ssh", now()); ok {
		t.Fatal("a revoked grant is not active")
	}
}

func TestSweeper(t *testing.T) {
	ctx, r := setup(t)
	// A grant already past its window.
	lapsed := &Request{UserID: "u1", TargetID: "t1", Protocol: "ssh", Reason: "x", RequestedMinutes: 1}
	if err := r.Create(ctx, lapsed); err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().Add(-time.Minute)
	if _, err := r.Decide(ctx, lapsed.ID, "u2", StatusApproved, "", &past); err != nil {
		t.Fatal(err)
	}
	// A still-active grant that must survive the sweep.
	active := &Request{UserID: "u1", TargetID: "t1", Protocol: "ssh", Reason: "y", RequestedMinutes: 60}
	if err := r.Create(ctx, active); err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(time.Hour)
	if _, err := r.Decide(ctx, active.ID, "u2", StatusApproved, "", &future); err != nil {
		t.Fatal(err)
	}

	sw := &Sweeper{Repo: r, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	n, err := sw.Sweep(ctx)
	if err != nil || n != 1 {
		t.Fatalf("sweep should expire exactly the lapsed grant: n=%d err=%v", n, err)
	}
	if g, _ := r.Get(ctx, lapsed.ID); g.Status != StatusExpired {
		t.Fatalf("lapsed grant should be expired, got %s", g.Status)
	}
	if g, _ := r.Get(ctx, active.ID); g.Status != StatusApproved {
		t.Fatalf("active grant should survive, got %s", g.Status)
	}
	if n, _ := sw.Sweep(ctx); n != 0 {
		t.Fatalf("a second sweep should expire nothing, got %d", n)
	}
}
