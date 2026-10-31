// SPDX-License-Identifier: Apache-2.0

package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

func testRepo(t *testing.T) *Repo {
	t.Helper()
	db := storetest.Open(t)
	return NewRepo(db)
}

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$", hashParams.memory, hashParams.time, hashParams.threads); !strings.HasPrefix(h, want) {
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
	if got.IsBlocked() {
		t.Fatal("a temporary lock refuses new sign-ins only; it does not block the account")
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
	if !got.IsLocked(time.Now()) || !got.IsBlocked() {
		t.Fatal("disabled accounts count as locked and blocked")
	}
}

// idpRow stores a bare identity provider row for users.idp_id to reference.
// Package idp imports user, so the row is written by hand rather than
// through idp.Repo.
func idpRow(t *testing.T, r *Repo, name string) string {
	t.Helper()
	id, now := store.NewID(), store.TimeArg(time.Now())
	if _, err := r.db.ExecContext(context.Background(), r.db.Rebind(`INSERT INTO identity_providers (id, name, type, config_enc, enabled, created_at, updated_at)
		VALUES (?, ?, 'oidc', ?, TRUE, ?, ?)`), id, name, []byte{0}, now, now); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestLinkExternal: LinkExternal ties an account to an identity provider's
// subject, so the next sign-in through that provider finds it by external id.
// It writes the link and nothing else (roles, password, profile and status
// stay the administrator's), answers not-found for an unknown account, and
// refuses to give a subject that is already linked a second account.
func TestLinkExternal(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	corp := idpRow(t, r, "corp")
	alice := &User{Username: "alice", Email: "alice@example.com", DisplayName: "Alice", Roles: []Role{RoleAdmin}}
	if err := r.Create(ctx, alice); err != nil {
		t.Fatal(err)
	}

	if err := r.LinkExternal(ctx, alice.ID, corp, "sub-1"); err != nil {
		t.Fatalf("link: %v", err)
	}
	got, err := r.GetByExternalID(ctx, corp, "sub-1")
	if err != nil || got.ID != alice.ID || got.IdPID != corp || got.ExternalID != "sub-1" {
		t.Fatalf("by external id after the link: %+v %v", got, err)
	}
	if got.Username != "alice" || got.DisplayName != "Alice" || got.Email != "alice@example.com" || got.PasswordHash != "" ||
		got.Status != StatusActive || len(got.Roles) != 1 || got.Roles[0] != RoleAdmin {
		t.Fatalf("the link changed more than the link: %+v", got)
	}

	if err := r.LinkExternal(ctx, "no-such-user", corp, "sub-2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown account: got %v, want ErrNotFound", err)
	}
	bob := &User{Username: "bob", DisplayName: "Bob", Roles: []Role{RoleUser}}
	if err := r.Create(ctx, bob); err != nil {
		t.Fatal(err)
	}
	if err := r.LinkExternal(ctx, bob.ID, corp, "sub-1"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("a subject already linked to alice: got %v, want ErrDuplicate", err)
	}
	// The link is written only while the account is still linkable: an
	// account linked meanwhile, or given a password meanwhile, is refused
	// rather than overwritten (S1 L4).
	if err := r.LinkExternal(ctx, alice.ID, corp, "sub-9"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("relinking alice: got %v, want ErrDuplicate", err)
	}
	if got, _ := r.GetByID(ctx, alice.ID); got.ExternalID != "sub-1" {
		t.Fatalf("alice's link changed: %+v", got)
	}
	if err := r.SetPasswordHash(ctx, bob.ID, "$argon2id$not-really", false); err != nil {
		t.Fatal(err)
	}
	if err := r.LinkExternal(ctx, bob.ID, corp, "sub-2"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("linking an account with a password: got %v, want ErrDuplicate", err)
	}
}

func TestCanConnect(t *testing.T) {
	cases := []struct {
		roles []Role
		want  bool
	}{
		{[]Role{RoleUser}, true},
		{[]Role{RoleAdmin}, true},
		{[]Role{RoleAuditor}, false},
		{[]Role{RoleAuditor, RoleUser}, true},
		{[]Role{RoleAuditor, RoleAdmin}, true},
		{nil, false},
	}
	for _, c := range cases {
		u := &User{Roles: c.roles}
		if got := u.CanConnect(); got != c.want {
			t.Errorf("roles %v: CanConnect = %v, want %v", c.roles, got, c.want)
		}
	}
}

// TestValidUsernameTakesAddresses (ADR 0035): a provider such as Okta or
// Entra ID asserts an email address or UPN as the username, so the address
// form is a username too. Neither form takes a space, quote, slash, control
// character or a second "@", and an address is bounded as SMTP bounds one.
func TestValidUsernameTakesAddresses(t *testing.T) {
	for _, ok := range []string{
		"alice", "a.b-c_d", "alice@corp.example", "alice.smith+ops@corp.example", "a@b.co", "first.last@sub.corp-x.example",
		"x" + strings.Repeat("y", 63) + "@corp.example",
	} {
		if !ValidUsername(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	long := strings.Repeat("a", 60) + "@" + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + "." + strings.Repeat("e", 60) + ".example" // 312 characters
	for _, bad := range []string{
		"", "a", "-alice", ".alice@corp.example", "alice@", "@corp.example", "alice@corp", "alice@@corp.example", "alice@corp.example.",
		"alice@-corp.example", "alice@corp-.example", "al ice@corp.example", "alice@corp example", "a/b@corp.example", `a"b@corp.example`,
		"alice@corp.example\n", "alice\x00@corp.example", "alice@corp_x.example", "a+b", "x" + strings.Repeat("y", 64) + "@corp.example", long,
	} {
		if ValidUsername(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestProviderSignIn (2026-10-31): the console tells an account that signs
// in through an identity provider from one made with a password. The flag is
// derived on create and on every read, and is never a stored secret.
func TestProviderSignIn(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	hash, err := HashPassword("a password of its own")
	if err != nil {
		t.Fatal(err)
	}
	local := &User{Username: "local-one", DisplayName: "Local One", PasswordHash: hash, Status: StatusActive, Roles: []Role{RoleUser}}
	waiting := &User{Username: "waits-for-sso", DisplayName: "Waits", Status: StatusActive, Roles: []Role{RoleUser}}
	for _, u := range []*User{local, waiting} {
		if err := r.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	if local.ProviderSignIn || !waiting.ProviderSignIn {
		t.Fatalf("on create: local %v, waiting %v", local.ProviderSignIn, waiting.ProviderSignIn)
	}
	all, _, err := r.List(ctx, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, u := range all {
		got[u.Username] = u.ProviderSignIn
	}
	if got["local-one"] || !got["waits-for-sso"] {
		t.Fatalf("on read: %v", got)
	}
}
