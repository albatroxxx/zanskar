// SPDX-License-Identifier: Apache-2.0

package user

import (
	"context"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// TestDirectoryMarkOnEachBackend (ADR 0035): the sync disables an active
// account and marks it; only a marked, disabled account is enabled again;
// an administrator's change of status clears the mark, while writing the
// status the account already has keeps it. ListByIdP returns the linked
// accounts only, with roles. Timestamps and the CASE in Update run on both
// engines.
func TestDirectoryMarkOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		now := time.Now().UTC().Truncate(time.Second)
		if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO identity_providers (id, name, type, config_enc, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`),
			"idp1", "kc", "oidc", []byte("x"), true, store.TimeArg(now), store.TimeArg(now)); err != nil {
			t.Fatal(err)
		}
		mk := func(name string, linked bool) *User {
			t.Helper()
			u := &User{Username: name, DisplayName: name, Roles: []Role{RoleUser}}
			if err := r.Create(ctx, u); err != nil {
				t.Fatal(err)
			}
			if linked {
				if err := r.LinkExternal(ctx, u.ID, "idp1", "ext-"+name); err != nil {
					t.Fatal(err)
				}
			}
			return u
		}
		left, admin, local := mk("left", true), mk("admin-off", true), mk("local", false)

		got, err := r.ListByIdP(ctx, "idp1")
		if err != nil || len(got) != 2 || len(got[0].Roles) != 1 {
			t.Fatalf("ListByIdP: %d %v", len(got), err)
		}
		for _, u := range got {
			if u.ID == local.ID {
				t.Fatal("ListByIdP returned an unlinked account")
			}
		}

		if ok, err := r.DisableRemoved(ctx, left.ID, now); err != nil || !ok {
			t.Fatalf("DisableRemoved: %v %v", ok, err)
		}
		u, _ := r.GetByID(ctx, left.ID)
		if u.Status != StatusDisabled || u.DirectoryRemovedAt == nil || !u.DirectoryRemovedAt.Equal(now) {
			t.Fatalf("after DisableRemoved: %s %v", u.Status, u.DirectoryRemovedAt)
		}
		if ok, _ := r.DisableRemoved(ctx, left.ID, now); ok {
			t.Fatal("DisableRemoved twice must report false")
		}
		// The profile written with the same status keeps the mark.
		if err := r.Update(ctx, left.ID, "Left Person", "", StatusDisabled); err != nil {
			t.Fatal(err)
		}
		if u, _ := r.GetByID(ctx, left.ID); u.DirectoryRemovedAt == nil {
			t.Fatal("writing the same status must keep the mark")
		}
		if ok, err := r.EnableReturned(ctx, left.ID); err != nil || !ok {
			t.Fatalf("EnableReturned: %v %v", ok, err)
		}
		if u, _ := r.GetByID(ctx, left.ID); u.Status != StatusActive || u.DirectoryRemovedAt != nil {
			t.Fatalf("after EnableReturned: %s %v", u.Status, u.DirectoryRemovedAt)
		}

		// An administrator disables: no mark, and the sync never enables it.
		if err := r.Update(ctx, admin.ID, admin.DisplayName, "", StatusDisabled); err != nil {
			t.Fatal(err)
		}
		if ok, _ := r.EnableReturned(ctx, admin.ID); ok {
			t.Fatal("an account an administrator disabled must not be enabled by the sync")
		}
		if ok, _ := r.DisableRemoved(ctx, admin.ID, now); ok {
			t.Fatal("DisableRemoved must leave a disabled account alone")
		}
		// A sync-disabled account the administrator enables is theirs now.
		if _, err := r.DisableRemoved(ctx, left.ID, now); err != nil {
			t.Fatal(err)
		}
		if err := r.Update(ctx, left.ID, "Left Person", "", StatusActive); err != nil {
			t.Fatal(err)
		}
		if u, _ := r.GetByID(ctx, left.ID); u.Status != StatusActive || u.DirectoryRemovedAt != nil {
			t.Fatalf("an administrator's enable must clear the mark: %s %v", u.Status, u.DirectoryRemovedAt)
		}
	})
}

// TestProvisionedOnEachBackend (ADR 0035, SCIM): an administrator's
// password-less account is provisioned for a provider without a subject,
// listed for that provider only and filtered by username (any case),
// externalId and id with paging; renamed; hidden once deleted over SCIM;
// and bound to a subject by the first sign-in, after which it cannot be
// bound again.
func TestProvisionedOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		now := time.Now().UTC().Truncate(time.Second)
		for _, id := range []string{"p1", "p2"} {
			if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO identity_providers (id, name, type, config_enc, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`),
				id, id, "oidc", []byte("x"), true, store.TimeArg(now), store.TimeArg(now)); err != nil {
				t.Fatal(err)
			}
		}
		pre := &User{Username: "pre@corp.example", DisplayName: "Pre", Roles: []Role{RoleAuditor}}
		pushed := &User{Username: "Pushed@Corp.example", DisplayName: "Pushed", Roles: []Role{RoleUser}, IdPID: "p1", SCIMExternalID: "ext-1"}
		other := &User{Username: "other@corp.example", DisplayName: "Other", Roles: []Role{RoleUser}, IdPID: "p2"}
		pw := &User{Username: "pw", DisplayName: "PW", Roles: []Role{RoleUser}, PasswordHash: "$argon2id$x"}
		for _, u := range []*User{pre, pushed, other, pw} {
			if err := r.Create(ctx, u); err != nil {
				t.Fatal(err)
			}
		}
		if err := r.Provision(ctx, pre.ID, "p1", "ext-pre"); err != nil {
			t.Fatal(err)
		}
		if err := r.Provision(ctx, pw.ID, "p1", ""); err != ErrDuplicate {
			t.Fatalf("a password account must not be provisioned: %v", err)
		}
		if err := r.Provision(ctx, other.ID, "p1", ""); err != ErrDuplicate {
			t.Fatalf("another provider's account must not be provisioned: %v", err)
		}
		all, total, err := r.ListProvisioned(ctx, "p1", SCIMFilter{}, 0, 10)
		if err != nil || total != 2 || len(all) != 2 || all[0].Username != "pre@corp.example" || len(all[0].Roles) != 1 {
			t.Fatalf("list: %d %v", total, err)
		}
		if page, total, _ := r.ListProvisioned(ctx, "p1", SCIMFilter{}, 1, 1); total != 2 || len(page) != 1 || page[0].ID != pushed.ID {
			t.Fatalf("page: %d %v", total, page)
		}
		for _, f := range []SCIMFilter{{"userName", "PUSHED@corp.example"}, {"externalId", "ext-1"}, {"id", pushed.ID}} {
			got, n, err := r.ListProvisioned(ctx, "p1", f, 0, 10)
			if err != nil || n != 1 || got[0].ID != pushed.ID {
				t.Fatalf("filter %v: %d %v", f, n, err)
			}
		}
		if _, _, err := r.ListProvisioned(ctx, "p1", SCIMFilter{"title", "x"}, 0, 10); err == nil {
			t.Fatal("an unknown filter attribute must be refused")
		}
		if err := r.Rename(ctx, pushed.ID, "renamed@corp.example"); err != nil {
			t.Fatal(err)
		}
		if err := r.Rename(ctx, pushed.ID, "PRE@corp.example"); err != ErrDuplicate {
			t.Fatalf("rename onto another account: %v", err)
		}
		at := now.Add(time.Minute)
		if err := r.SetSCIM(ctx, pre.ID, "ext-pre", &at); err != nil {
			t.Fatal(err)
		}
		if _, n, _ := r.ListProvisioned(ctx, "p1", SCIMFilter{"id", pre.ID}, 0, 10); n != 0 {
			t.Fatal("a deleted account must be hidden")
		}
		if u, _ := r.GetByID(ctx, pre.ID); u.SCIMDeletedAt == nil || !u.SCIMDeletedAt.Equal(at) || u.SCIMExternalID != "ext-pre" {
			t.Fatalf("scim fields: %+v", u)
		}
		// The first sign-in binds the subject; a second subject cannot.
		if err := r.LinkExternal(ctx, pushed.ID, "p1", "sub-1"); err != nil {
			t.Fatal(err)
		}
		if err := r.LinkExternal(ctx, pushed.ID, "p1", "sub-2"); err != ErrDuplicate {
			t.Fatalf("rebinding: %v", err)
		}
		if err := r.LinkExternal(ctx, other.ID, "p1", "sub-3"); err != ErrDuplicate {
			t.Fatalf("binding another provider's account: %v", err)
		}
	})
}
