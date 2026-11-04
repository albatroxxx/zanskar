// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/albatroxxx/zanskar/internal/group"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestReviewListsOnlyThoseWhoCanConnect (2026-11-04, live walkthrough): an
// access review listed a review-only auditor as covered by a policy and
// "never used", though an account that holds only auditor is refused whatever
// a policy says. A group of an auditor and a user lists the user.
func TestReviewListsOnlyThoseWhoCanConnect(t *testing.T) {
	ctx := context.Background()
	db := storetest.Open(t)
	users, groups := user.NewRepo(db), group.NewRepo(db)
	mk := func(name string, roles ...user.Role) string {
		t.Helper()
		u := &user.User{Username: name, DisplayName: name, Roles: roles}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		return u.ID
	}
	auditor, plain, admin := mk("auditor", user.RoleAuditor), mk("plain", user.RoleUser), mk("boss", user.RoleAdmin)
	g := &group.Group{Name: "mixed"}
	if err := groups.CreateWithMembers(ctx, g, []string{auditor, plain, admin}); err != nil {
		t.Fatal(err)
	}

	name, people, err := reviewDirectory{users: users, groups: groups}.Group(ctx, g.ID)
	if err != nil || name != "mixed" {
		t.Fatalf("group: %q %v", name, err)
	}
	var got []string
	for _, p := range people {
		got = append(got, p.Username)
	}
	if len(got) != 2 || got[0] != "boss" || got[1] != "plain" {
		t.Fatalf("the review lists %v, want boss and plain", got)
	}
}
