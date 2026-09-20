// SPDX-License-Identifier: Apache-2.0

package group

import (
	"context"
	"errors"
	"testing"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

func testDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(context.Background(), config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func mkUser(t *testing.T, users *user.Repo, name string) *user.User {
	t.Helper()
	u := &user.User{Username: name, DisplayName: name, Roles: []user.Role{user.RoleUser}}
	if err := users.Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestGroupCRUDAndMembers(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	r := NewRepo(db)
	users := user.NewRepo(db)
	a, b, c := mkUser(t, users, "ua"), mkUser(t, users, "ub"), mkUser(t, users, "uc")

	g := &Group{Name: " ops ", Description: "operators"}
	if err := r.Create(ctx, g); err != nil || g.ID == "" || g.Name != "ops" {
		t.Fatalf("create: %v %+v", err, g)
	}
	if err := r.Create(ctx, &Group{Name: "ops"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected duplicate, got %v", err)
	}
	if err := r.Create(ctx, &Group{Name: ""}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid input, got %v", err)
	}
	for _, n := range []string{"dev", "sec"} {
		if err := r.Create(ctx, &Group{Name: n}); err != nil {
			t.Fatal(err)
		}
	}
	page, next, err := r.List(ctx, "", 2)
	if err != nil || len(page) != 2 || next != "ops" {
		t.Fatalf("list: %d next=%q err=%v", len(page), next, err)
	}

	added, removed, err := r.SetMembers(ctx, g.ID, []string{a.ID, b.ID})
	if err != nil || len(added) != 2 || len(removed) != 0 {
		t.Fatalf("set members: %v %v %v", added, removed, err)
	}
	added, removed, err = r.SetMembers(ctx, g.ID, []string{b.ID, c.ID})
	if err != nil || len(added) != 1 || added[0] != c.ID || len(removed) != 1 || removed[0] != a.ID {
		t.Fatalf("replace: added=%v removed=%v err=%v", added, removed, err)
	}
	if _, _, err := r.SetMembers(ctx, g.ID, []string{"ghost"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown user should be rejected, got %v", err)
	}
	members, err := r.Members(ctx, g.ID)
	if err != nil || len(members) != 2 || members[0].Username != "ub" || members[0].AddedAt.IsZero() {
		t.Fatalf("members: %+v %v", members, err)
	}
	got, _ := r.Get(ctx, g.ID)
	if got.MemberCount != 2 {
		t.Fatalf("member_count = %d", got.MemberCount)
	}
	if err := r.AddMember(ctx, g.ID, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := r.AddMember(ctx, g.ID, a.ID); err != nil {
		t.Fatal("adding twice must be a no-op")
	}
	if err := r.RemoveMember(ctx, g.ID, c.ID); err != nil {
		t.Fatal(err)
	}
	mine, err := r.GroupsForUser(ctx, a.ID)
	if err != nil || len(mine) != 1 || mine[0].ID != g.ID {
		t.Fatalf("groups for user: %+v %v", mine, err)
	}
	full, err := r.MemberUsers(ctx, g.ID)
	if err != nil || len(full) != 2 {
		t.Fatalf("member users: %d %v", len(full), err)
	}

	if err := r.Update(ctx, g.ID, "dev", ""); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("rename to existing must fail, got %v", err)
	}
	if err := r.Update(ctx, g.ID, "operations", "renamed"); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(ctx, g.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("expected not found after delete")
	}
	if mine, _ := r.GroupsForUser(ctx, a.ID); len(mine) != 0 {
		t.Fatal("membership must cascade on delete")
	}
	if err := r.Delete(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleting unknown group must be not found")
	}
}

func TestSyncedGroupRejectsManualMembership(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO identity_providers (id, name, type, config_enc, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, TRUE, ?, ?)`),
		"idp1", "corp", "oidc", []byte{1}, store.TimeArg(store.NullTime{}.Time), store.TimeArg(store.NullTime{}.Time)); err != nil {
		t.Fatal(err)
	}
	r := NewRepo(db)
	g := &Group{Name: "synced", IdPID: "idp1", ExternalID: "ext"}
	if err := r.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.SetMembers(ctx, g.ID, nil); !errors.Is(err, ErrSynced) {
		t.Fatalf("expected ErrSynced, got %v", err)
	}
}
