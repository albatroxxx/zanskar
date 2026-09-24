// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
)

func TestSelectorMatches(t *testing.T) {
	s := Selector{Targets: []string{"t1"}, ASGs: []string{"a1"}, Tags: map[string]string{"env": "prod", "team": "ops"}}
	cases := []struct {
		ref  TargetRef
		want bool
	}{
		{TargetRef{ID: "t1"}, true},
		{TargetRef{ID: "t2"}, false},
		{TargetRef{ASGID: "a1"}, true},
		{TargetRef{ID: "t9", Tags: map[string]string{"env": "prod", "team": "ops", "extra": "x"}}, true},
		{TargetRef{ID: "t9", Tags: map[string]string{"env": "prod"}}, false},
		{TargetRef{ID: "t9", Tags: map[string]string{"env": "dev", "team": "ops"}}, false},
	}
	for i, c := range cases {
		if got := s.Matches(c.ref); got != c.want {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
	if (Selector{}).Matches(TargetRef{ID: "t1", Tags: map[string]string{"a": "b"}}) {
		t.Error("empty selector must match nothing")
	}
}

func TestTimeWindow(t *testing.T) {
	w := TimeWindow{Days: []string{"mon", "tue"}, From: "09:00", To: "18:00", TZ: "UTC"}
	if err := w.validate(); err != nil {
		t.Fatal(err)
	}
	mon10 := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC) // Monday
	mon19 := time.Date(2026, 9, 21, 19, 0, 0, 0, time.UTC)
	wed10 := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	if !w.Open(mon10) || w.Open(mon19) || w.Open(wed10) {
		t.Fatal("daytime window wrong")
	}
	night := TimeWindow{Days: []string{"fri"}, From: "22:00", To: "06:00", TZ: "Asia/Kolkata"}
	if err := night.validate(); err != nil {
		t.Fatal(err)
	}
	loc, _ := time.LoadLocation("Asia/Kolkata")
	fri23 := time.Date(2026, 9, 25, 23, 0, 0, 0, loc)
	sat03 := time.Date(2026, 9, 26, 3, 0, 0, 0, loc)
	sat07 := time.Date(2026, 9, 26, 7, 0, 0, 0, loc)
	thu23 := time.Date(2026, 9, 24, 23, 0, 0, 0, loc)
	if !night.Open(fri23) || !night.Open(sat03) || night.Open(sat07) || night.Open(thu23) {
		t.Fatal("overnight window wrong")
	}
	bad := TimeWindow{Days: []string{"funday"}, From: "09:00", To: "18:00"}
	if err := bad.validate(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("expected invalid day")
	}
	bad = TimeWindow{Days: []string{"mon"}, From: "9am", To: "18:00"}
	if err := bad.validate(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("expected invalid clock")
	}
}

func TestEvaluate(t *testing.T) {
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC) // Monday 10:00
	max := 60
	wide := &Policy{Name: "wide", Enabled: true, Selector: Selector{Tags: map[string]string{"env": "prod"}}, Protocols: []string{"ssh", "rdp"}, IdleTimeoutMinutes: 30, AllowClipboard: true}
	tight := &Policy{Name: "tight", Enabled: true, Selector: Selector{Targets: []string{"t1"}}, Protocols: []string{"ssh"}, IdleTimeoutMinutes: 10, MaxSessionMinutes: &max, RequireMFA: true}
	off := &Policy{Name: "off", Enabled: false, Selector: Selector{Targets: []string{"t1"}}, Protocols: []string{"vnc"}, IdleTimeoutMinutes: 5}
	hours := &Policy{Name: "hours", Enabled: true, Selector: Selector{Targets: []string{"t2"}}, Protocols: []string{"ssh"}, IdleTimeoutMinutes: 15,
		TimeWindows: []TimeWindow{{Days: []string{"sat", "sun"}, From: "00:00", To: "23:59", TZ: "UTC"}}}
	all := []*Policy{wide, tight, off, hours}

	prod := TargetRef{ID: "t1", Tags: map[string]string{"env": "prod"}}
	d := Evaluate(all, prod, "ssh", now)
	if !d.Allowed || d.Policy != tight || d.IdleTimeout != 10*time.Minute || d.MaxSession != time.Hour || d.AllowClipboard {
		t.Fatalf("expected tight policy to win on overlap: %+v", d)
	}
	d = Evaluate(all, prod, "rdp", now)
	if !d.Allowed || d.Policy != wide || !d.AllowClipboard {
		t.Fatalf("expected wide policy for rdp: %+v", d)
	}
	if d := Evaluate(all, prod, "vnc", now); d.Allowed {
		t.Fatal("disabled policy must not grant vnc")
	}
	if d := Evaluate(all, TargetRef{ID: "t2"}, "ssh", now); d.Allowed || d.Reason != "outside the policy's access window" {
		t.Fatalf("weekday access to weekend policy: %+v", d)
	}
	if d := Evaluate(all, TargetRef{ID: "t2"}, "ssh", now.AddDate(0, 0, 5)); !d.Allowed {
		t.Fatal("saturday access should be allowed")
	}
	if d := Evaluate(all, TargetRef{ID: "t3", Tags: map[string]string{"env": "dev"}}, "ssh", now); d.Allowed {
		t.Fatal("dev target must be denied")
	}
}

func TestRepo(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	// Minimal fixtures: a group and a user in it.
	now := store.TimeArg(time.Now())
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, db.Rebind(q), args...); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(`INSERT INTO groups (id, name, created_at, updated_at) VALUES ('g1', 'ops', ?, ?)`, now, now)
	mustExec(`INSERT INTO groups (id, name, created_at, updated_at) VALUES ('g2', 'dev', ?, ?)`, now, now)
	mustExec(`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1', 'alice', 'Alice', ?, ?)`, now, now)
	mustExec(`INSERT INTO group_members (group_id, user_id, added_at) VALUES ('g1', 'u1', ?)`, now)

	r := NewRepo(db)
	p := &Policy{Name: "prod-ssh", GroupID: "g1", Enabled: true, Selector: Selector{Tags: map[string]string{"env": "prod"}}, Protocols: []string{"ssh"}, IdleTimeoutMinutes: 15, RequireMFA: true}
	if err := r.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := r.Create(ctx, &Policy{Name: "prod-ssh", GroupID: "g1", Selector: Selector{Targets: []string{"x"}}, Protocols: []string{"ssh"}, IdleTimeoutMinutes: 15}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected duplicate, got %v", err)
	}
	if err := r.Create(ctx, &Policy{Name: "orphan", GroupID: "nope", Selector: Selector{Targets: []string{"x"}}, Protocols: []string{"ssh"}, IdleTimeoutMinutes: 15}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid group, got %v", err)
	}
	if err := r.Create(ctx, &Policy{Name: "dev", GroupID: "g2", Enabled: true, Selector: Selector{Targets: []string{"x"}}, Protocols: []string{"rdp"}, IdleTimeoutMinutes: 15}); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(ctx, p.ID)
	if err != nil || got.Name != "prod-ssh" || got.Selector.Tags["env"] != "prod" || len(got.TimeWindows) != 0 {
		t.Fatalf("get: %+v %v", got, err)
	}
	mine, err := r.ForUser(ctx, "u1")
	if err != nil || len(mine) != 1 || mine[0].ID != p.ID {
		t.Fatalf("ForUser: %d policies err=%v", len(mine), err)
	}
	p.Enabled = false
	if err := r.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	if mine, _ = r.ForUser(ctx, "u1"); len(mine) != 0 {
		t.Fatal("disabled policy must not be returned for user")
	}
	list, next, err := r.List(ctx, "", 1)
	if err != nil || len(list) != 1 || next != "dev" {
		t.Fatalf("list: %d next=%q err=%v", len(list), next, err)
	}
	if err := r.Delete(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("expected not found after delete")
	}
}

// TestRepoUserScopedPolicy covers policies bound to one user rather than a
// group (ADR 0013): they reach that user and nobody else, they combine with
// the user's group policies, and a policy must name exactly one subject.
func TestRepoUserScopedPolicy(t *testing.T) {
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
	for _, q := range []string{
		`INSERT INTO groups (id, name, created_at, updated_at) VALUES ('g1', 'ops', ?, ?)`,
		`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1', 'alice', 'Alice', ?, ?)`,
		`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u2', 'bob', 'Bob', ?, ?)`,
	} {
		if _, err := db.ExecContext(ctx, db.Rebind(q), now, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO group_members (group_id, user_id, added_at) VALUES ('g1', 'u1', ?)`), now); err != nil {
		t.Fatal(err)
	}
	r := NewRepo(db)
	sel := Selector{Tags: map[string]string{"env": "prod"}}
	groupPol := &Policy{Name: "ops", GroupID: "g1", Enabled: true, Selector: sel, Protocols: []string{"ssh"}, IdleTimeoutMinutes: 15}
	bobPol := &Policy{Name: "bob-only", UserID: "u2", Enabled: true, Selector: sel, Protocols: []string{"rdp"}, IdleTimeoutMinutes: 15}
	alicePol := &Policy{Name: "alice-extra", UserID: "u1", Enabled: true, Selector: sel, Protocols: []string{"winrm"}, IdleTimeoutMinutes: 15}
	for _, p := range []*Policy{groupPol, bobPol, alicePol} {
		if err := r.Create(ctx, p); err != nil {
			t.Fatalf("create %s: %v", p.Name, err)
		}
	}

	names := func(ps []*Policy) []string {
		out := []string{}
		for _, p := range ps {
			out = append(out, p.Name)
		}
		return out
	}
	alice, err := r.ForUser(ctx, "u1")
	if err != nil || len(alice) != 2 || alice[0].Name != "alice-extra" || alice[1].Name != "ops" {
		t.Fatalf("alice gets her own policy plus her group's: %v %v", names(alice), err)
	}
	bob, err := r.ForUser(ctx, "u2")
	if err != nil || len(bob) != 1 || bob[0].Name != "bob-only" || bob[0].UserID != "u2" || bob[0].GroupID != "" {
		t.Fatalf("bob, in no group, gets only his own policy: %v %v", names(bob), err)
	}

	// A policy must name exactly one subject, and it must exist.
	for _, bad := range []*Policy{
		{Name: "none", Selector: sel, Protocols: []string{"ssh"}, IdleTimeoutMinutes: 15},
		{Name: "both", GroupID: "g1", UserID: "u1", Selector: sel, Protocols: []string{"ssh"}, IdleTimeoutMinutes: 15},
		{Name: "ghost", UserID: "nobody", Selector: sel, Protocols: []string{"ssh"}, IdleTimeoutMinutes: 15},
	} {
		if err := r.Create(ctx, bad); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s: expected invalid input, got %v", bad.Name, err)
		}
	}

	// Moving a policy from a group to a user, and back, round-trips.
	groupPol.GroupID, groupPol.UserID = "", "u1"
	if err := r.Update(ctx, groupPol); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(ctx, groupPol.ID)
	if err != nil || got.UserID != "u1" || got.GroupID != "" {
		t.Fatalf("update to user subject: %+v %v", got, err)
	}
	if bob, _ = r.ForUser(ctx, "u2"); len(bob) != 1 {
		t.Fatalf("bob unaffected by alice's policies: %v", names(bob))
	}
}

func TestValidateProtocols(t *testing.T) {
	base := func(protos ...string) *Policy {
		return &Policy{Name: "p", UserID: "u1", Selector: Selector{Targets: []string{"t1"}},
			Protocols: protos, IdleTimeoutMinutes: 30}
	}
	// database is a first-class protocol a policy may grant (ADR 0017).
	for _, protos := range [][]string{{"database"}, {"ssh", "database"}} {
		if err := base(protos...).Validate(); err != nil {
			t.Fatalf("protocols %v should validate, got %v", protos, err)
		}
	}
	if err := base("mysqlx").Validate(); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown protocol should be rejected, got %v", err)
	}
}
