// SPDX-License-Identifier: Apache-2.0

package group

import (
	"context"
	"errors"
	"testing"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestRepoOnEachBackend proves the group repository on both engines: the
// LOWER()-ordered listing and paging, the members join and the
// groups-for-user lookup (review Q1, finding 2). Names are unique as written,
// not case-insensitively; the listing order is what LOWER() decides.
func TestRepoOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		users := user.NewRepo(db)
		a, b := mkUser(t, users, "ua"), mkUser(t, users, "ub")
		ops := &Group{Name: "Ops", Description: "operators"}
		if err := r.Create(ctx, ops); err != nil {
			t.Fatal(err)
		}
		if err := r.Create(ctx, &Group{Name: "Ops"}); !errors.Is(err, ErrDuplicate) {
			t.Fatalf("the same name again must be a duplicate, got %v", err)
		}
		for _, n := range []string{"dev", "Sec"} {
			if err := r.Create(ctx, &Group{Name: n}); err != nil {
				t.Fatal(err)
			}
		}
		page, next, err := r.List(ctx, "", 2)
		if err != nil || len(page) != 2 || next == "" || page[0].Name != "dev" || page[1].Name != "Ops" {
			t.Fatalf("first page (case-insensitive order): %+v next=%q err=%v", page, next, err)
		}
		rest, _, err := r.List(ctx, next, 2)
		if err != nil || len(rest) != 1 || rest[0].Name != "Sec" {
			t.Fatalf("second page: %+v err=%v", rest, err)
		}
		if added, removed, err := r.SetMembers(ctx, ops.ID, []string{a.ID, b.ID}); err != nil || len(added) != 2 || len(removed) != 0 {
			t.Fatalf("set members: %v %v %v", added, removed, err)
		}
		members, err := r.Members(ctx, ops.ID)
		if err != nil || len(members) != 2 {
			t.Fatalf("members: %+v %v", members, err)
		}
		groups, err := r.GroupsForUser(ctx, a.ID)
		if err != nil || len(groups) != 1 || groups[0].ID != ops.ID || groups[0].MemberCount != 2 {
			t.Fatalf("groups for user: %+v %v", groups, err)
		}
		if err := r.RemoveMember(ctx, ops.ID, b.ID); err != nil {
			t.Fatal(err)
		}
		if got, err := r.Get(ctx, ops.ID); err != nil || got.MemberCount != 1 {
			t.Fatalf("member count after removal: %+v %v", got, err)
		}
	})
}

// TestCreateWithMembersOnEachBackend (2026-10-30): a group can be made with
// its members in one step; an unknown user refuses all of it, so no empty
// group is left behind, and repeated or blank ids are taken once.
func TestCreateWithMembersOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		users := user.NewRepo(db)
		var ids []string
		for _, n := range []string{"ann", "ben"} {
			u := &user.User{Username: n, DisplayName: n, Roles: []user.Role{user.RoleUser}}
			if err := users.Create(ctx, u); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, u.ID)
		}
		r := NewRepo(db)
		g := &Group{Name: "ops"}
		if err := r.CreateWithMembers(ctx, g, []string{ids[0], ids[1], ids[0], " "}); err != nil {
			t.Fatal(err)
		}
		members, err := r.Members(ctx, g.ID)
		if err != nil || len(members) != 2 {
			t.Fatalf("members: %+v %v", members, err)
		}
		bad := &Group{Name: "sre"}
		if err := r.CreateWithMembers(ctx, bad, []string{ids[0], "no-such-user"}); !errors.Is(err, ErrUnknownUser) {
			t.Fatalf("unknown user: %v", err)
		}
		if _, _, err := r.List(ctx, "", 50); err != nil {
			t.Fatal(err)
		}
		all, _, _ := r.List(ctx, "", 50)
		for _, x := range all {
			if x.Name == "sre" {
				t.Fatal("a refused group was left behind")
			}
		}
	})
}
