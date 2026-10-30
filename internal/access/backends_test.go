// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// TestRepoOnEachBackend proves the request repository's time comparisons on
// both engines (TIMESTAMPTZ keeps microseconds, SQLite keeps text): an
// approved grant is active until its expiry and not after, the expiry sweep
// finds exactly the due rows, and a second decision is refused (review Q1,
// finding 2).
func TestRepoOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		stamp := store.TimeArg(time.Now())
		for _, q := range []string{
			`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1', 'alice', 'Alice', ?, ?)`,
			`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u2', 'bob', 'Bob', ?, ?)`,
			`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t1', 'web1', '10.0.0.1', 'linux', ?, ?)`,
		} {
			if _, err := db.ExecContext(ctx, db.Rebind(q), stamp, stamp); err != nil {
				t.Fatal(err)
			}
		}
		r := NewRepo(db)
		now := time.Now().UTC()
		req := &Request{UserID: "u1", TargetID: "t1", Protocol: "ssh", Reason: "deploy", RequestedMinutes: 60}
		if err := r.Create(ctx, req); err != nil {
			t.Fatal(err)
		}
		if n, err := r.CountPending(ctx); err != nil || n != 1 {
			t.Fatalf("pending: %d %v", n, err)
		}
		exp := now.Add(time.Hour)
		got, err := r.Decide(ctx, req.ID, "u2", StatusApproved, "ok", &exp, 45)
		if err != nil || got.Status != StatusApproved || got.ApprovedMinutes != 45 || got.ExpiresAt == nil {
			t.Fatalf("approve: %+v %v", got, err)
		}
		if _, err := r.Decide(ctx, req.ID, "u2", StatusDenied, "", nil, 0); !errors.Is(err, ErrState) {
			t.Fatalf("a second decision must be ErrState, got %v", err)
		}
		if ok, err := r.HasActiveGrant(ctx, "u1", "t1", "", "ssh", now.Add(59*time.Minute)); err != nil || !ok {
			t.Fatalf("active one minute before expiry: %v %v", ok, err)
		}
		if ok, err := r.HasActiveGrant(ctx, "u1", "t1", "", "ssh", now.Add(61*time.Minute)); err != nil || ok {
			t.Fatalf("active after expiry: %v %v", ok, err)
		}
		if ok, err := r.HasActiveGrant(ctx, "u1", "t1", "", "rdp", now); err != nil || ok {
			t.Fatalf("a grant for ssh must not cover rdp: %v %v", ok, err)
		}
		if due, err := r.DueForExpiry(ctx, now.Add(30*time.Minute)); err != nil || len(due) != 0 {
			t.Fatalf("nothing is due before the expiry: %+v %v", due, err)
		}
		due, err := r.DueForExpiry(ctx, now.Add(2*time.Hour))
		if err != nil || len(due) != 1 || due[0].ID != req.ID {
			t.Fatalf("due after the expiry: %+v %v", due, err)
		}
		if n, err := r.ExpireDue(ctx, now.Add(2*time.Hour)); err != nil || n != 1 {
			t.Fatalf("expire: %d %v", n, err)
		}
		if again, err := r.Get(ctx, req.ID); err != nil || again.Status != StatusExpired {
			t.Fatalf("after the sweep: %+v %v", again, err)
		}
		if list, err := r.ListByUser(ctx, "u1"); err != nil || len(list) != 1 || list[0].ExpiresAt == nil || list[0].ExpiresAt.Sub(exp).Abs() > time.Second {
			t.Fatalf("the stored expiry must read back as the same instant: %+v %v", list, err)
		}
	})
}

// TestCloseForTargetOnEachBackend (ADR 0036, amended 2026-10-30): deleting a
// target revokes its pending and approved requests inside the deletion's
// transaction, with the reason, and leaves decided ones and another
// target's alone; the count before matches.
func TestCloseForTargetOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		stamp := store.TimeArg(time.Now())
		for _, q := range []string{
			`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1', 'alice', 'Alice', ?, ?)`,
			`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u2', 'bob', 'Bob', ?, ?)`,
			`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t1', 'web1', '10.0.0.1', 'linux', ?, ?)`,
			`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t2', 'web2', '10.0.0.2', 'linux', ?, ?)`,
		} {
			if _, err := db.ExecContext(ctx, db.Rebind(q), stamp, stamp); err != nil {
				t.Fatal(err)
			}
		}
		r := NewRepo(db)
		mk := func(target string) *Request {
			req := &Request{UserID: "u1", TargetID: target, Protocol: "ssh", Reason: "deploy", RequestedMinutes: 60}
			if err := r.Create(ctx, req); err != nil {
				t.Fatal(err)
			}
			return req
		}
		pending, approved, denied, other := mk("t1"), mk("t1"), mk("t1"), mk("t2")
		exp := time.Now().Add(time.Hour)
		if _, err := r.Decide(ctx, approved.ID, "u2", StatusApproved, "ok", &exp, 60); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Decide(ctx, denied.ID, "u2", StatusDenied, "no", nil, 0); err != nil {
			t.Fatal(err)
		}
		if n, err := r.OpenForTarget(ctx, "t1", ""); err != nil || n != 2 {
			t.Fatalf("open for t1: %d %v", n, err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		n, err := r.CloseForTargetTx(ctx, tx, "t1", "", "target deleted")
		if err != nil || n != 2 {
			t.Fatalf("closed: %d %v", n, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			req  *Request
			want Status
		}{{pending, StatusRevoked}, {approved, StatusRevoked}, {denied, StatusDenied}, {other, StatusPending}} {
			got, err := r.Get(ctx, c.req.ID)
			if err != nil || got.Status != c.want {
				t.Fatalf("%s: %+v %v, want %s", c.req.ID, got, err, c.want)
			}
		}
		if got, _ := r.Get(ctx, pending.ID); got.DecisionNote != "target deleted" {
			t.Fatalf("note: %q", got.DecisionNote)
		}
	})
}
