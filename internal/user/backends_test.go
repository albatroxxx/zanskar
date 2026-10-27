// SPDX-License-Identifier: Apache-2.0

package user

import (
	"context"
	"errors"
	"testing"

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
