// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"testing"

	"github.com/albatroxxx/zanskar/internal/idp"
)

// TestUsernameAcrossProviders (ADR 0035): the claims the common providers
// send, as their documentation describes them, each give a usable
// username. Okta's preferred_username is the login, an address; Entra ID's
// is the UPN and it never says whether an email is verified; Google sends
// no preferred_username; Keycloak and Authentik send a plain name. An
// address used as the username must be one the provider vouches for.
func TestUsernameAcrossProviders(t *testing.T) {
	cases := []struct {
		name   string
		cfg    idp.OIDCConfig
		claims map[string]any
		want   string // "" means refused
	}{
		{"okta", idp.OIDCConfig{UsernameClaim: "preferred_username"},
			map[string]any{"preferred_username": "Alice.Smith@Corp.example", "email": "alice.smith@corp.example", "email_verified": true}, "alice.smith@corp.example"},
		{"entra id", idp.OIDCConfig{UsernameClaim: "preferred_username", TrustEmail: true},
			map[string]any{"preferred_username": "bob@corp.onmicrosoft.com", "email": "bob@corp.example"}, "bob@corp.onmicrosoft.com"},
		{"google", idp.OIDCConfig{UsernameClaim: "preferred_username"},
			map[string]any{"email": "carol@corp.example", "email_verified": true}, "carol@corp.example"},
		{"google, address not verified", idp.OIDCConfig{UsernameClaim: "preferred_username"},
			map[string]any{"email": "carol@corp.example", "email_verified": false}, ""},
		{"keycloak", idp.OIDCConfig{UsernameClaim: "preferred_username"},
			map[string]any{"preferred_username": "dave", "email": "dave@corp.example", "email_verified": true}, "dave"},
		{"email claim, verified", idp.OIDCConfig{UsernameClaim: "email"},
			map[string]any{"preferred_username": "erin", "email": "Erin@Corp.example", "email_verified": "true"}, "erin@corp.example"},
		{"email claim, not verified", idp.OIDCConfig{UsernameClaim: "email"},
			map[string]any{"preferred_username": "mallory", "email": "boss@corp.example", "email_verified": false}, ""},
		{"email claim, provider never says, not trusted", idp.OIDCConfig{UsernameClaim: "email"},
			map[string]any{"email": "boss@corp.example"}, ""},
		{"email claim, provider never says, trusted", idp.OIDCConfig{UsernameClaim: "email", TrustEmail: true},
			map[string]any{"email": "frank@corp.example"}, "frank@corp.example"},
	}
	for _, tc := range cases {
		got, _, err := identityFromClaims("sub-1", tc.claims, &tc.cfg)
		if tc.want == "" {
			if err == nil {
				t.Errorf("%s: want refused, got %q", tc.name, got.Username)
			}
			continue
		}
		if err != nil || got.Username != tc.want {
			t.Errorf("%s: got %q %v, want %q", tc.name, got.Username, err, tc.want)
		}
	}
}

// TestOktaStyleSignIn: a sign-in whose username is an address, as Okta and
// Entra ID send it, provisions and completes; it used to be refused as an
// unusable username.
func TestOktaStyleSignIn(t *testing.T) {
	f := newFakeIdP(t)
	f.claims = map[string]any{"preferred_username": "Grace@Corp.example", "email": "grace@corp.example", "email_verified": true, "name": "Grace H"}
	e, id := newEnv(t, f, idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s"}, AutoProvision: true})
	if status, location, cookies := drive(t, e, f, id); status != 302 || location != "/admin" || !hasSession(cookies) {
		t.Fatalf("callback: %d %s", status, location)
	}
	u, err := e.users.GetByUsername(context.Background(), "grace@corp.example")
	if err != nil || u.ExternalID != "sub-1" || u.DisplayName != "Grace H" {
		t.Fatalf("user: %+v %v", u, err)
	}
}
