// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"context"
	"errors"
	"testing"

	"github.com/albatroxxx/zanskar/internal/user"
)

// TestSecondFactor: a policy that requires MFA (ADR 0035) is met by a
// Zanskar authenticator, or by an account that signs in only through an
// OIDC provider whose sign-in is the second factor. An LDAP account, a
// provider marked zanskar_mfa, a disabled provider and a local password
// account all still need the authenticator.
func TestSecondFactor(t *testing.T) {
	ctx := context.Background()
	e := newProvisionEnv(t)
	create := func(name string, typ Type, c *Config, enabled bool) string {
		t.Helper()
		p := &Provider{Name: name, Type: typ, Enabled: enabled}
		if err := e.repo.Create(ctx, p, c); err != nil {
			t.Fatal(err)
		}
		return p.ID
	}
	ownsMFA := create("kc", TypeOIDC, okOIDC(), true)
	marked := okOIDC()
	marked.OIDC.ZanskarMFA = true
	asksZanskar := create("no-mfa", TypeOIDC, marked, true)
	off := create("off", TypeOIDC, okOIDC(), false)
	dir := create("ad", TypeLDAP, okLDAP(), true)

	linked := func(username, idpID, hash string) string {
		t.Helper()
		u := e.local(t, username, hash)
		if idpID != "" {
			if err := e.users.LinkExternal(ctx, u.ID, idpID, "ext-"+username); err != nil {
				t.Fatal(err)
			}
		}
		return u.ID
	}
	enrolledIDs := map[string]bool{}
	check := SecondFactor(e.users, e.repo, func(_ context.Context, id string) (bool, error) { return enrolledIDs[id], nil })

	cases := []struct {
		name     string
		userID   string
		enrolled bool
		want     bool
	}{
		{"oidc provider owns MFA", linked("kc-user", ownsMFA, ""), false, true},
		{"oidc provider marked zanskar_mfa", linked("nomfa-user", asksZanskar, ""), false, false},
		{"oidc provider marked zanskar_mfa, enrolled", linked("nomfa-enrolled", asksZanskar, ""), true, true},
		{"disabled provider", linked("off-user", off, ""), false, false},
		{"ldap directory", linked("ad-user", dir, ""), false, false},
		{"local password account", linked("local", "", aHash), false, false},
		{"local password account, enrolled", linked("local-enrolled", "", aHash), true, true},
	}
	for _, tc := range cases {
		enrolledIDs[tc.userID] = tc.enrolled
		got, err := check(ctx, tc.userID)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v %v, want %v", tc.name, got, err, tc.want)
		}
	}

	// A provider deleted since the account was linked leaves idp_id NULL:
	// the account has nothing vouching for it.
	gone := linked("gone-user", create("gone", TypeOIDC, okOIDC(), true), "")
	if err := e.repo.Delete(ctx, e.get(t, gone).IdPID); err != nil {
		t.Fatal(err)
	}
	if got, err := check(ctx, gone); err != nil || got {
		t.Fatalf("deleted provider: got %v %v", got, err)
	}

	// The enrolment lookup failing is an error, not a no.
	boom := errors.New("boom")
	failing := SecondFactor(e.users, e.repo, func(context.Context, string) (bool, error) { return false, boom })
	if _, err := failing(ctx, cases[0].userID); !errors.Is(err, boom) {
		t.Fatalf("lookup error: %v", err)
	}
	if _, err := check(ctx, "no-such-user"); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}
