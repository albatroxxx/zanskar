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
