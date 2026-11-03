// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// The security contact setting, which published /.well-known/security.txt,
// was withdrawn on 2026-11-04 at the owner's decision. A gateway that ran
// 1.15.0 to 1.18.0 may hold the address an administrator stored for it, and
// migration 0053 deletes that row.
const (
	lastWithSecurityContact = "0052_drop_acme_cache"
	forgetSecurityContact   = "0053_forget_security_contact"
)

// Nothing offers the setting any more: it is not in the list the panel draws
// from, and setting it through the API is refused as unknown.
func TestSecurityContactIsNoLongerASetting(t *testing.T) {
	if _, ok := Lookup("security.contact"); ok {
		t.Fatal("security.contact is still a setting")
	}
	svc := NewService(NewRepo(storetest.Open(t)), nil, nil)
	for _, v := range svc.All() {
		if v.Key == "security.contact" {
			t.Fatalf("the panel would still list it: %+v", v)
		}
	}
	if _, err := svc.Set(context.Background(), "security.contact", "security@example.com", ""); !errors.Is(err, ErrUnknown) {
		t.Fatalf("setting it must be refused as unknown: %v", err)
	}
}

// On each backend, a database at the last schema that had the setting, holding
// a stored contact beside another setting, loses the contact and only the
// contact to migration 0053; loading before it ran skips the stale row, and a
// refused set stores nothing.
func TestMigrationForgetsTheSecurityContact(t *testing.T) {
	storetest.ForEachBackendUpTo(t, lastWithSecurityContact, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		now := store.TimeArg(time.Now())
		for key, value := range map[string]string{"security.contact": "security@example.com", KeyLoginBanner: "Authorised use only."} {
			if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)`), key, value, now); err != nil {
				t.Fatal(err)
			}
		}
		repo := NewRepo(db)
		svc := NewService(repo, nil, nil)
		// Before the migration the row is still there, and a start that loads it
		// does not fail on a key that is no longer a setting.
		if err := svc.Load(ctx); err != nil {
			t.Fatalf("a stored row for a setting that no longer exists must not stop loading: %v", err)
		}
		if v, _ := svc.Get(KeyLoginBanner); v.Value != "Authorised use only." || v.Source != SourceConsole {
			t.Fatalf("the other setting must load beside the stale row: %+v", v)
		}

		ran, err := store.MigrateTo(ctx, db, forgetSecurityContact)
		if err != nil || len(ran) != 1 || ran[0] != forgetSecurityContact {
			t.Fatalf("migrate: ran %v, err %v; want only %s", ran, err, forgetSecurityContact)
		}
		all, err := repo.All(ctx)
		if err != nil || len(all) != 1 || all[0].Key != KeyLoginBanner || all[0].Value != "Authorised use only." {
			t.Fatalf("only the contact goes; the other setting stays: %+v %v", all, err)
		}
		if _, err := svc.Set(ctx, "security.contact", "security@example.com", ""); !errors.Is(err, ErrUnknown) {
			t.Fatalf("setting it again must be refused as unknown: %v", err)
		}
		if got, err := repo.Get(ctx, "security.contact"); err != nil || got.Value != "" || got.UpdatedAt != nil {
			t.Fatalf("a refused set must store nothing: %+v %v", got, err)
		}
	})
}
