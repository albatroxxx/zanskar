// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"context"
	"testing"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestRepoOnEachBackend proves the settings row upsert (ON CONFLICT on the
// key) and the read-back on both engines, then the service's precedence over
// it (review Q1, finding 2).
func TestRepoOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		users := user.NewRepo(db)
		first := &user.User{Username: "first", DisplayName: "First", Roles: []user.Role{user.RoleAdmin}}
		second := &user.User{Username: "second", DisplayName: "Second", Roles: []user.Role{user.RoleAdmin}}
		for _, u := range []*user.User{first, second} {
			if err := users.Create(ctx, u); err != nil {
				t.Fatal(err)
			}
		}
		r := NewRepo(db)
		if _, err := r.Set(ctx, KeyLogLevel, "debug", first.ID); err != nil {
			t.Fatal(err)
		}
		again, err := r.Set(ctx, KeyLogLevel, "warn", second.ID)
		if err != nil || again.Value != "warn" || again.UpdatedBy != second.ID || again.UpdatedAt == nil {
			t.Fatalf("the second set is an upsert: %+v %v", again, err)
		}
		all, err := r.All(ctx)
		if err != nil || len(all) != 1 || all[0].Key != KeyLogLevel {
			t.Fatalf("all after two sets of one key: %+v %v", all, err)
		}
		svc := NewService(r, map[string]string{KeyLogLevel: "info"}, nil)
		if err := svc.Load(ctx); err != nil {
			t.Fatal(err)
		}
		if v, _ := svc.Get(KeyLogLevel); v.Value != "warn" || v.Source != SourceConsole {
			t.Fatalf("the console row must win over the environment: %+v", v)
		}
		if err := r.Delete(ctx, KeyLogLevel); err != nil {
			t.Fatal(err)
		}
		if err := svc.Load(ctx); err != nil {
			t.Fatal(err)
		}
		if v, _ := svc.Get(KeyLogLevel); v.Value != "info" || v.Source != SourceEnvironment {
			t.Fatalf("after the row is gone the environment applies: %+v", v)
		}
	})
}
