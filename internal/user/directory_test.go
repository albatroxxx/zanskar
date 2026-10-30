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
