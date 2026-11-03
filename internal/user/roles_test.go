// SPDX-License-Identifier: Apache-2.0

package user

import (
	"context"
	"io/fs"
	"slices"
	"testing"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/migrations"
)

// 2026-11-03: an administrator reviews what an auditor reviews and connects
// as a user does, so the console offering all three ticked at once kept
// roles that said nothing more. Roles are kept with admin alone.

func TestNormalizeRoles(t *testing.T) {
	for _, c := range []struct{ in, want []Role }{
		{nil, []Role{}},
		{[]Role{RoleUser}, []Role{RoleUser}},
		{[]Role{RoleUser, RoleAuditor, RoleUser}, []Role{RoleAuditor, RoleUser}},
		{[]Role{RoleAdmin}, []Role{RoleAdmin}},
		{[]Role{RoleUser, RoleAdmin, RoleAuditor}, []Role{RoleAdmin}},
		{[]Role{RoleAuditor, RoleAdmin, RoleAdmin}, []Role{RoleAdmin}},
		// One it does not know is kept, for ValidRole to refuse.
		{[]Role{"root", RoleUser}, []Role{RoleUser, "root"}},
	} {
		if got := NormalizeRoles(c.in); !slices.Equal(got, c.want) {
			t.Fatalf("%v: %v, want %v", c.in, got, c.want)
		}
	}
}

func TestRolesAreKeptWithAdminAlone(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		u := &User{Username: "ann", DisplayName: "Ann", Roles: []Role{RoleUser}}
		if err := r.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		// Made an administrator with the other two still ticked: admin alone.
		if err := r.SetRoles(ctx, u.ID, []Role{RoleUser, RoleAuditor, RoleAdmin}); err != nil {
			t.Fatal(err)
		}
		got, err := r.GetByID(ctx, u.ID)
		if err != nil || !slices.Equal(got.Roles, []Role{RoleAdmin}) {
			t.Fatalf("roles: %v %v", got.Roles, err)
		}
		// No longer an administrator: what is asked for, each once.
		other := &User{Username: "bea", DisplayName: "Bea", Roles: []Role{RoleAdmin}}
		if err := r.Create(ctx, other); err != nil {
			t.Fatal(err)
		}
		if err := r.SetRoles(ctx, u.ID, []Role{RoleUser, RoleAuditor, RoleUser}); err != nil {
			t.Fatal(err)
		}
		if got, _ := r.GetByID(ctx, u.ID); !slices.Equal(got.Roles, []Role{RoleAuditor, RoleUser}) {
			t.Fatalf("after admin: %v", got.Roles)
		}
	})
}

// Migration 0047 leaves an administrator kept before with all three roles
// holding admin alone, and everyone else as they were.
func TestMigrationKeepsAdminAlone(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		admin := &User{Username: "old-admin", DisplayName: "Old", Roles: []Role{RoleAdmin}}
		plain := &User{Username: "both", DisplayName: "Both", Roles: []Role{RoleAuditor, RoleUser}}
		for _, u := range []*User{admin, plain} {
			if err := r.Create(ctx, u); err != nil {
				t.Fatal(err)
			}
		}
		// As 1.15.0 kept it: admin beside the other two.
		for _, role := range []string{"auditor", "user"} {
			if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO user_roles (user_id, role) VALUES (?, ?)`), admin.ID, role); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.ExecContext(ctx, migration0047(t)); err != nil {
			t.Fatal(err)
		}
		if got, _ := r.GetByID(ctx, admin.ID); !slices.Equal(got.Roles, []Role{RoleAdmin}) {
			t.Fatalf("an administrator kept with all three: %v", got.Roles)
		}
		if got, _ := r.GetByID(ctx, plain.ID); !slices.Equal(got.Roles, []Role{RoleAuditor, RoleUser}) {
			t.Fatalf("an auditor and user is left alone: %v", got.Roles)
		}
	})
}

// migration0047 is the migration's SQL, the same on both engines.
func migration0047(t *testing.T) string {
	t.Helper()
	b, err := fs.ReadFile(migrations.FS, "sqlite/0047_admin_roles_alone.sql")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
