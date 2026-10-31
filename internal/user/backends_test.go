// SPDX-License-Identifier: Apache-2.0

package user

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// TestRepoOnEachBackend proves the user repository's engine-sensitive
// queries on SQLite and, in CI, on PostgreSQL: the LOWER() lookups by
// username, the case-insensitive uniqueness, paging by username and the
// lockout timestamps (review Q1, finding 2).
func TestRepoOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		alice := &User{Username: "Alice", Email: "alice@example.com", DisplayName: "Alice", Roles: []Role{RoleAdmin, RoleUser}}
		if err := r.Create(ctx, alice); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"bob", "carol"} {
			if err := r.Create(ctx, &User{Username: n, DisplayName: n, Roles: []Role{RoleUser}}); err != nil {
				t.Fatal(err)
			}
		}
		for _, lookup := range []string{"alice", "ALICE", "Alice"} {
			got, err := r.GetByUsername(ctx, lookup)
			if err != nil || got.ID != alice.ID || !got.HasRole(RoleAdmin) {
				t.Fatalf("GetByUsername(%q): %+v %v", lookup, got, err)
			}
		}
		if err := r.Create(ctx, &User{Username: "aLiCe", DisplayName: "dup"}); !errors.Is(err, ErrDuplicate) {
			t.Fatalf("a username that differs in case only must be a duplicate, got %v", err)
		}
		page, next, err := r.List(ctx, "", 2)
		if err != nil || len(page) != 2 || next == "" {
			t.Fatalf("first page: %d next=%q err=%v", len(page), next, err)
		}
		rest, next2, err := r.List(ctx, next, 2)
		if err != nil || len(rest) != 1 || next2 != "" {
			t.Fatalf("second page: %d next=%q err=%v", len(rest), next2, err)
		}
		if page[0].Username != "alice" || page[1].Username != "bob" || rest[0].Username != "carol" {
			t.Fatalf("paging order: %s %s %s", page[0].Username, page[1].Username, rest[0].Username)
		}
		if locked, err := r.RecordLoginFailure(ctx, alice.ID, 1, 15*60e9); err != nil || !locked {
			t.Fatalf("one failure with a limit of one must lock: %v %v", locked, err)
		}
		got, err := r.GetByID(ctx, alice.ID)
		if err != nil || got.LockedUntil == nil || !got.LockedUntil.After(got.CreatedAt) {
			t.Fatalf("locked_until after a lock: %+v %v", got.LockedUntil, err)
		}
		if err := r.RecordLoginSuccess(ctx, alice.ID); err != nil {
			t.Fatal(err)
		}
		if got, err = r.GetByID(ctx, alice.ID); err != nil || got.LockedUntil != nil || got.FailedLogins != 0 || got.LastLoginAt == nil {
			t.Fatalf("after a success: %+v %v", got, err)
		}
	})
}

// TestCreateInGroupsOnEachBackend (2026-10-30): a user can be made a member
// of groups as the account is created, in one step; a group that does not
// exist, or whose members come from an identity provider, refuses all of it.
func TestCreateInGroupsOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		zero := store.TimeArg(store.NullTime{}.Time)
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO identity_providers (id, name, type, config_enc, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, TRUE, ?, ?)`, []any{"idp1", "corp", "oidc", []byte{1}, zero, zero}},
			{`INSERT INTO groups (id, name, description, created_at, updated_at) VALUES (?, ?, '', ?, ?)`, []any{"g-ops", "ops", zero, zero}},
			{`INSERT INTO groups (id, name, description, created_at, updated_at) VALUES (?, ?, '', ?, ?)`, []any{"g-dba", "dba", zero, zero}},
			{`INSERT INTO groups (id, name, description, idp_id, external_id, created_at, updated_at) VALUES (?, ?, '', ?, ?, ?, ?)`, []any{"g-synced", "synced", "idp1", "ext", zero, zero}},
		} {
			if _, err := db.ExecContext(ctx, db.Rebind(q.sql), q.args...); err != nil {
				t.Fatal(err)
			}
		}
		r := NewRepo(db)
		ann := &User{Username: "ann", DisplayName: "Ann", Roles: []Role{RoleUser}}
		if err := r.CreateInGroups(ctx, ann, []string{"g-ops", "g-dba", "g-ops", ""}); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := db.QueryRowContext(ctx, db.Rebind(`SELECT COUNT(*) FROM group_members WHERE user_id = ?`), ann.ID).Scan(&n); err != nil || n != 2 {
			t.Fatalf("memberships: %d %v", n, err)
		}
		for _, bad := range []string{"g-none", "g-synced"} {
			u := &User{Username: "ben-" + bad, DisplayName: "Ben", Roles: []Role{RoleUser}}
			if err := r.CreateInGroups(ctx, u, []string{"g-ops", bad}); !errors.Is(err, ErrUnknownGroup) {
				t.Fatalf("%s: %v", bad, err)
			}
			if _, err := r.GetByUsername(ctx, u.Username); !errors.Is(err, ErrNotFound) {
				t.Fatalf("%s: a refused account was left behind: %v", bad, err)
			}
		}
	})
}

// TestCountPostureOnEachBackend (2026-10-31, the dashboard's security
// posture): who counts as not yet enrolled for each shape of account, who is
// dormant at 90 days, and how many administrators there are, on SQLite and
// PostgreSQL (timestamp comparison, an IN list built per call).
func TestCountPostureOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		now := time.Now().UTC()
		exec := func(q string, args ...any) {
			t.Helper()
			if _, err := db.ExecContext(ctx, db.Rebind(q), args...); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		for _, p := range [][2]string{{"p-owns", "oidc"}, {"p-ldap", "ldap"}, {"p-zmfa", "oidc"}} {
			exec(`INSERT INTO identity_providers (id, name, type, config_enc, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				p[0], p[0], p[1], []byte("sealed"), true, store.TimeArg(now), store.TimeArg(now))
		}
		add := func(name, hash, idp string, roles []Role, status Status) string {
			t.Helper()
			u := &User{Username: name, DisplayName: name, PasswordHash: hash, IdPID: idp, Roles: roles, Status: status}
			if idp != "" {
				u.ExternalID = "sub-" + name
			}
			if err := r.Create(ctx, u); err != nil {
				t.Fatal(err)
			}
			return u.ID
		}
		totp := func(id string, confirmed bool) {
			var at any
			if confirmed {
				at = store.TimeArg(now)
			}
			exec(`INSERT INTO mfa_totp (user_id, secret_enc, confirmed_at, created_at) VALUES (?, ?, ?, ?)`, id, []byte("s"), at, store.TimeArg(now))
		}
		users := []Role{RoleUser}
		local := add("local", "hash", "", users, StatusActive)                    // counts
		enrolled := add("enrolled", "hash", "", users, StatusActive)              // has one
		half := add("half", "hash", "", users, StatusActive)                      // started, not confirmed: counts
		add("waiting", "", "", users, StatusActive)                               // no password, no link yet
		add("sso", "", "p-owns", users, StatusActive)                             // provider owns MFA
		add("ldap", "", "p-ldap", users, StatusActive)                            // counts
		add("zmfa", "", "p-zmfa", users, StatusActive)                            // provider leaves it to Zanskar: counts
		add("gone", "hash", "", users, StatusDisabled)                            // disabled: never counted
		admin1 := add("admin1", "hash", "", []Role{RoleAdmin}, StatusActive)      // counts as admin, enrolled below
		add("admin-off", "hash", "", []Role{RoleAdmin, RoleUser}, StatusDisabled) // disabled admin: not counted
		totp(enrolled, true)
		totp(half, false)
		totp(admin1, true)

		p, err := r.CountPosture(ctx, now, []string{"p-owns"})
		if err != nil {
			t.Fatal(err)
		}
		if p.NotEnrolled != 4 || p.Admins != 1 || p.Dormant != 0 {
			t.Fatalf("posture %+v, want not enrolled 4 (local, half, ldap, zmfa), admins 1, dormant 0", p)
		}
		// With no provider owning MFA, the linked SSO account needs one too.
		if p, err = r.CountPosture(ctx, now, nil); err != nil || p.NotEnrolled != 5 {
			t.Fatalf("no provider owns MFA: %+v %v", p, err)
		}

		// Dormant: last sign-in, else creation, older than 90 days.
		old := store.TimeArg(now.Add(-DormantAfter - time.Hour))
		exec(`UPDATE users SET last_login_at = ? WHERE id = ?`, old, local)
		exec(`UPDATE users SET created_at = ? WHERE username = ?`, old, "waiting")
		exec(`UPDATE users SET created_at = ?, last_login_at = ? WHERE id = ?`, old, store.TimeArg(now), enrolled)
		exec(`UPDATE users SET last_login_at = ? WHERE username = ?`, old, "gone")
		if p, err = r.CountPosture(ctx, now, []string{"p-owns"}); err != nil || p.Dormant != 2 {
			t.Fatalf("dormant: %+v %v, want local and waiting", p, err)
		}
	})
}
