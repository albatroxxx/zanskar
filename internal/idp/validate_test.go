// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"errors"
	"testing"

	"github.com/albatroxxx/zanskar/internal/user"
)

func okOIDC() *Config {
	return &Config{OIDC: &OIDCConfig{Issuer: "https://login.example.com", ClientID: "zanskar", ClientSecret: "s"}}
}

func okLDAP() *Config {
	return &Config{LDAP: &LDAPConfig{URL: "ldaps://dc1.corp.example:636", CACertPEM: "-----BEGIN CERTIFICATE-----",
		BindDN: "CN=svc,DC=corp", BaseDN: "DC=corp", UserFilter: "(sAMAccountName=%s)"}}
}

// TestValidateRefusesWeakConfigurations: a provider that would send
// credentials or tokens without protection, or trust anything it is told, is
// refused before it is stored. OIDC needs an https issuer; LDAP needs TLS
// (ldaps://, or ldap:// with StartTLS) and a CA to verify the directory
// unless insecure mode is chosen explicitly; the user filter must place the
// username; default roles must be real roles.
func TestValidateRefusesWeakConfigurations(t *testing.T) {
	cases := []struct {
		name string
		typ  Type
		cfg  func() *Config
	}{
		{"oidc over plain http", TypeOIDC, func() *Config { c := okOIDC(); c.OIDC.Issuer = "http://login.example.com"; return c }},
		{"oidc without a client secret", TypeOIDC, func() *Config { c := okOIDC(); c.OIDC.ClientSecret = ""; return c }},
		{"oidc with an ldap config", TypeOIDC, func() *Config { c := okOIDC(); c.LDAP = okLDAP().LDAP; return c }},
		{"plain ldap without StartTLS", TypeLDAP, func() *Config { c := okLDAP(); c.LDAP.URL = "ldap://dc1.corp.example"; return c }},
		{"ldap with another scheme", TypeLDAP, func() *Config { c := okLDAP(); c.LDAP.URL = "https://dc1"; return c }},
		{"ldap with no CA and no explicit insecure", TypeLDAP, func() *Config { c := okLDAP(); c.LDAP.CACertPEM = ""; return c }},
		{"ldap filter without the username", TypeLDAP, func() *Config { c := okLDAP(); c.LDAP.UserFilter = "(objectClass=user)"; return c }},
		{"ldap without a bind DN", TypeLDAP, func() *Config { c := okLDAP(); c.LDAP.BindDN = ""; return c }},
		{"unknown default role", TypeOIDC, func() *Config { c := okOIDC(); c.DefaultRoles = []user.Role{"superuser"}; return c }},
		{"unknown provider type", Type("saml"), okOIDC},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := Validate(&Provider{Name: "corp", Type: c.typ}, c.cfg()); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("got %v, want ErrInvalidInput", err)
			}
		})
	}
	for _, name := range []string{"", "   ", string(make([]byte, 65))} {
		if err := Validate(&Provider{Name: name, Type: TypeOIDC}, okOIDC()); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("name %q accepted", name)
		}
	}
}

// TestValidateAcceptsAndFillsDefaults: sound configurations pass, StartTLS
// and an explicit insecure mode included, and empty optional fields get
// their documented defaults (users get the user role; OIDC asks for openid,
// profile and email; LDAP reads Active Directory's usual attributes).
func TestValidateAcceptsAndFillsDefaults(t *testing.T) {
	o := okOIDC()
	if err := Validate(&Provider{Name: " corp ", Type: TypeOIDC}, o); err != nil {
		t.Fatal(err)
	}
	if len(o.DefaultRoles) != 1 || o.DefaultRoles[0] != user.RoleUser || len(o.OIDC.Scopes) != 3 || o.OIDC.UsernameClaim != "preferred_username" {
		t.Fatalf("oidc defaults: %+v %+v", o, o.OIDC)
	}

	l := okLDAP()
	l.LDAP.URL, l.LDAP.StartTLS = "ldap://dc1.corp.example", true
	if err := Validate(&Provider{Name: "ad", Type: TypeLDAP}, l); err != nil {
		t.Fatalf("ldap:// with StartTLS: %v", err)
	}
	if l.LDAP.UsernameAttr != "sAMAccountName" || l.LDAP.DisplayNameAttr != "displayName" || l.LDAP.EmailAttr != "mail" || l.LDAP.GroupNameAttr != "cn" {
		t.Fatalf("ldap defaults: %+v", l.LDAP)
	}
	dev := okLDAP()
	dev.LDAP.CACertPEM, dev.LDAP.InsecureSkipVerify = "", true
	if err := Validate(&Provider{Name: "lab", Type: TypeLDAP}, dev); err != nil {
		t.Fatalf("explicit insecure mode: %v", err)
	}
}

// TestValidateSync (ADR 0035): the user sync lists a Keycloak realm or an
// LDAP directory, gives each person the username a sign-in would, and runs
// every 5 minutes to once a day, 15 by default. Off, the interval is not
// kept.
func TestValidateSync(t *testing.T) {
	kc := func(issuer, claim string, minutes int) *Config {
		c := okOIDC()
		c.OIDC.Issuer, c.OIDC.UsernameClaim, c.SyncUsers, c.SyncMinutes = issuer, claim, true, minutes
		return c
	}
	realm := "https://kc.example/realms/zanskar"
	cases := []struct {
		name string
		typ  Type
		c    *Config
		ok   bool
		mins int
	}{
		{"keycloak, defaults", TypeOIDC, kc(realm, "", 0), true, 15},
		{"keycloak behind /auth", TypeOIDC, kc("https://sso.example/auth/realms/corp/", "email", 60), true, 60},
		{"keycloak by sub", TypeOIDC, kc(realm, "sub", 5), true, 5},
		{"not keycloak", TypeOIDC, kc("https://login.example.com", "", 0), false, 0},
		{"custom username claim", TypeOIDC, kc(realm, "upn", 0), false, 0},
		{"too often", TypeOIDC, kc(realm, "", 4), false, 0},
		{"too rarely", TypeOIDC, kc(realm, "", 1441), false, 0},
		{"ldap", TypeLDAP, func() *Config { c := okLDAP(); c.SyncUsers = true; return c }(), true, 15},
		{"off keeps no interval", TypeOIDC, func() *Config { c := kc(realm, "", 30); c.SyncUsers = false; return c }(), true, 0},
	}
	for _, tc := range cases {
		err := Validate(&Provider{Name: "p", Type: tc.typ}, tc.c)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if tc.ok && tc.c.SyncMinutes != tc.mins {
			t.Errorf("%s: interval %d, want %d", tc.name, tc.c.SyncMinutes, tc.mins)
		}
	}
}

// TestKeycloakRealm: the admin API sits beside the realm, under any path
// prefix the server has; anything that is not an https realm issuer is
// refused.
func TestKeycloakRealm(t *testing.T) {
	for issuer, want := range map[string]string{
		"https://kc.example/realms/zanskar":         "https://kc.example/admin/realms/zanskar",
		"https://kc.example/realms/zanskar/":        "https://kc.example/admin/realms/zanskar",
		"https://sso.example:8443/auth/realms/corp": "https://sso.example:8443/auth/admin/realms/corp",
	} {
		got, realm, err := KeycloakRealm(issuer)
		if err != nil || got != want || realm == "" {
			t.Errorf("%s: %s %s %v", issuer, got, realm, err)
		}
	}
	for _, bad := range []string{"http://kc.example/realms/zanskar", "https://kc.example/", "https://kc.example/realms/", "https://kc.example/realms/a/b",
		"https://kc.example/realms/x/realms/y", "https://kc.example/realms/z?x=1", "realms/z", ""} {
		if _, _, err := KeycloakRealm(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
