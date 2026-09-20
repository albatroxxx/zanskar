// SPDX-License-Identifier: Apache-2.0

package user

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
)

func testRepo(t *testing.T) *Repo {
	t.Helper()
	db, err := store.Open(context.Background(), config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return NewRepo(db)
}

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Fatalf("unexpected PHC prefix: %s", h)
	}
	if !VerifyPassword(h, "correct horse battery staple") {
		t.Fatal("expected match")
	}
	if VerifyPassword(h, "correct horse battery stapl") {
		t.Fatal("expected mismatch")
	}
	if VerifyPassword("garbage", "x") || VerifyPassword("$argon2id$v=19$m=0,t=0,p=0$AA$AA", "x") {
		t.Fatal("malformed hashes must not verify")
	}
	if NeedsRehash(h) {
		t.Fatal("fresh hash should not need rehash")
	}
	if !NeedsRehash("$argon2id$v=19$m=4096,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") {
		t.Fatal("weak params should need rehash")
	}
	if err := CheckPasswordPolicy("short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatal("expected weak password error")
	}
	if _, err := HashPassword(strings.Repeat("a", MaxPasswordLen+1)); err == nil {
		t.Fatal("expected over-length rejection")
	}
}

func TestCreateGetListRoles(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	u := &User{Username: "Alice", Email: "alice@example.com", DisplayName: "Alice", Roles: []Role{RoleAdmin, RoleUser, RoleUser}}
	if err := r.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if u.ID == "" || u.CreatedAt.IsZero() {
		t.Fatal("id and timestamps must be set")
	}
	got, err := r.GetByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != u.ID || len(got.Roles) != 2 || !got.HasRole(RoleAdmin) || got.Status != StatusActive {
		t.Fatalf("unexpected user: %+v", got)
	}
	if err := r.Create(ctx, &User{Username: "ALICE", DisplayName: "dup"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected duplicate, got %v", err)
	}
	if err := r.Create(ctx, &User{Username: "bad name!", DisplayName: "x"}); !errors.Is(err, ErrUsernameShape) {
		t.Fatalf("expected username shape error, got %v", err)
	}
	if err := r.Create(ctx, &User{Username: "bob", DisplayName: "Bob", Roles: []Role{"root"}}); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("expected invalid role, got %v", err)
	}
	for _, n := range []string{"bob", "carol", "dave"} {
		if err := r.Create(ctx, &User{Username: n, DisplayName: n, Roles: []Role{RoleUser}}); err != nil {
			t.Fatal(err)
		}
	}
	page, next, err := r.List(ctx, "", 2)
	if err != nil || len(page) != 2 || next != "bob" {
		t.Fatalf("page1: %d users next=%q err=%v", len(page), next, err)
	}
	page, next, err = r.List(ctx, next, 2)
	if err != nil || len(page) != 2 || next != "" {
		t.Fatalf("page2: %d users next=%q err=%v", len(page), next, err)
	}
	if _, err := r.GetByID(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal("expected not found")
	}
}

func TestLastAdminProtection(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	admin := &User{Username: "admin", DisplayName: "Admin", Roles: []Role{RoleAdmin}}
	if err := r.Create(ctx, admin); err != nil {
		t.Fatal(err)
	}
	if err := r.SetRoles(ctx, admin.ID, []Role{RoleUser}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("expected last admin error, got %v", err)
	}
	if err := r.Delete(ctx, admin.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("expected last admin error on delete, got %v", err)
	}
	second := &User{Username: "admin2", DisplayName: "Admin 2", Roles: []Role{RoleAdmin}}
	if err := r.Create(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := r.SetRoles(ctx, admin.ID, []Role{RoleAuditor}); err != nil {
		t.Fatalf("expected demotion to succeed with another admin, got %v", err)
	}
	n, _ := r.CountAdmins(ctx)
	if n != 1 {
		t.Fatalf("expected 1 admin, got %d", n)
	}
	if err := r.Delete(ctx, second.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatal("deleting the only remaining admin must fail")
	}
}

func TestLockout(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	u := &User{Username: "eve", DisplayName: "Eve", Roles: []Role{RoleUser}}
	if err := r.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 4; i++ {
		locked, err := r.RecordLoginFailure(ctx, u.ID, 5, time.Minute)
		if err != nil || locked {
			t.Fatalf("attempt %d: locked=%v err=%v", i, locked, err)
		}
	}
	locked, err := r.RecordLoginFailure(ctx, u.ID, 5, time.Minute)
	if err != nil || !locked {
		t.Fatalf("expected lock on 5th failure, locked=%v err=%v", locked, err)
	}
	got, _ := r.GetByID(ctx, u.ID)
	if !got.IsLocked(time.Now()) || got.LockedUntil == nil {
		t.Fatal("expected locked_until set")
	}
	if got.IsLocked(time.Now().Add(2 * time.Minute)) {
		t.Fatal("lock must expire")
	}
	if err := r.RecordLoginSuccess(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = r.GetByID(ctx, u.ID)
	if got.IsLocked(time.Now()) || got.LastLoginAt == nil || got.FailedLogins != 0 {
		t.Fatalf("expected cleared lock and last_login_at: %+v", got)
	}
	if err := r.Update(ctx, u.ID, "Eve", "", StatusDisabled); err != nil {
		t.Fatal(err)
	}
	got, _ = r.GetByID(ctx, u.ID)
	if !got.IsLocked(time.Now()) {
		t.Fatal("disabled accounts count as locked")
	}
}
