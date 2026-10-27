// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// TestRepoOnEachBackend proves the policy repository on both engines: the
// JSON columns (TEXT on SQLite, JSONB on PostgreSQL) round-trip selectors,
// rules and time windows, and the per-user and per-group lookups and the
// paging order hold (review Q1, finding 2).
func TestRepoOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		now := store.TimeArg(time.Now())
		mustExec := func(q string, args ...any) {
			t.Helper()
			if _, err := db.ExecContext(ctx, db.Rebind(q), args...); err != nil {
				t.Fatal(err)
			}
		}
		mustExec(`INSERT INTO groups (id, name, created_at, updated_at) VALUES ('g1', 'ops', ?, ?)`, now, now)
		mustExec(`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1', 'alice', 'Alice', ?, ?)`, now, now)
		mustExec(`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u2', 'bob', 'Bob', ?, ?)`, now, now)
		mustExec(`INSERT INTO group_members (group_id, user_id, added_at) VALUES ('g1', 'u1', ?)`, now)

		r := NewRepo(db)
		max := 90
		p := &Policy{Name: "prod-ssh", GroupID: "g1", Enabled: true,
			Selector:          Selector{Tags: map[string]string{"env": "prod", "tier": "web"}},
			Protocols:         []string{"ssh", "winrm"},
			Rules:             []Rule{{Selector: Selector{Targets: []string{"t-9"}}, Protocols: []string{"rdp"}}},
			TimeWindows:       []TimeWindow{{Days: []string{"mon", "tue", "wed", "thu", "fri"}, From: "09:00", To: "18:00", TZ: "Europe/Berlin"}},
			MaxSessionMinutes: &max, IdleTimeoutMinutes: 15, RequireMFA: true, AllowClipboard: true}
		if err := r.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
		direct := &Policy{Name: "bob-direct", UserID: "u2", Enabled: true, Selector: Selector{Targets: []string{"t-1"}}, Protocols: []string{"ssh"}, IdleTimeoutMinutes: 10}
		if err := r.Create(ctx, direct); err != nil {
			t.Fatal(err)
		}
		got, err := r.Get(ctx, p.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Selector.Tags["tier"] != "web" || len(got.Protocols) != 2 || len(got.Rules) != 1 || got.Rules[0].Protocols[0] != "rdp" ||
			len(got.TimeWindows) != 1 || got.TimeWindows[0].TZ != "Europe/Berlin" || len(got.TimeWindows[0].Days) != 5 ||
			got.MaxSessionMinutes == nil || *got.MaxSessionMinutes != 90 || !got.RequireMFA || !got.AllowClipboard {
			t.Fatalf("JSON columns did not round-trip: %+v", got)
		}
		forAlice, err := r.ForUser(ctx, "u1")
		if err != nil || len(forAlice) != 1 || forAlice[0].ID != p.ID {
			t.Fatalf("policies for a group member: %+v %v", forAlice, err)
		}
		forBob, err := r.ForUser(ctx, "u2")
		if err != nil || len(forBob) != 1 || forBob[0].ID != direct.ID {
			t.Fatalf("policies for a direct user: %+v %v", forBob, err)
		}
		forGroup, err := r.ForGroup(ctx, "g1")
		if err != nil || len(forGroup) != 1 {
			t.Fatalf("policies for the group: %+v %v", forGroup, err)
		}
		page, next, err := r.List(ctx, "", 1)
		if err != nil || len(page) != 1 || page[0].Name != "bob-direct" || next == "" {
			t.Fatalf("paging by name: %+v next=%q err=%v", page, next, err)
		}
		got.Enabled = false
		got.TimeWindows = nil
		if err := r.Update(ctx, got); err != nil {
			t.Fatal(err)
		}
		if again, err := r.Get(ctx, p.ID); err != nil || again.Enabled || len(again.TimeWindows) != 0 || again.UpdatedAt.Before(again.CreatedAt) {
			t.Fatalf("after update: %+v %v", again, err)
		}
		if err := r.Delete(ctx, p.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Get(ctx, p.ID); err == nil {
			t.Fatal("deleted policy still readable")
		}
	})
}
