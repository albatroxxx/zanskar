// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/albatroxxx/zanskar/internal/idp"
)

// fakeKeycloak serves what KeycloakDirectory reads: discovery, the token
// endpoint for client credentials, and the admin API's users and count.
type fakeKeycloak struct {
	srv   *httptest.Server
	mu    sync.Mutex
	users []keycloakUser
	// status, when set, answers the admin API with it.
	status int
	// countShift is added to every other count, as a realm changing while
	// it is read would.
	countShift int
	counts     int
	// extraCount is added to every count: users the listing never shows.
	extraCount int
	pageBytes  int
}

func newFakeKeycloak(t *testing.T) *fakeKeycloak {
	t.Helper()
	k := &fakeKeycloak{}
	mux := http.NewServeMux()
	issuer := func() string { return k.srv.URL + "/realms/zanskar" }
	mux.HandleFunc("GET /realms/zanskar/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer(), "authorization_endpoint": issuer() + "/auth",
			"token_endpoint": issuer() + "/token", "jwks_uri": issuer() + "/certs"})
	})
	mux.HandleFunc("POST /realms/zanskar/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		id, secret, ok := r.BasicAuth()
		if !ok {
			id, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
		}
		if r.Form.Get("grant_type") != "client_credentials" || id != "zanskar" || secret != "s" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized_client"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"admin-token","token_type":"Bearer","expires_in":300}`))
	})
	authorised := func(w http.ResponseWriter, r *http.Request) bool {
		k.mu.Lock()
		status := k.status
		k.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return false
		}
		if r.Header.Get("Authorization") != "Bearer admin-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /admin/realms/zanskar/users/count", func(w http.ResponseWriter, r *http.Request) {
		if !authorised(w, r) {
			return
		}
		k.mu.Lock()
		n := len(k.users) + k.extraCount
		if k.counts%2 == 1 {
			n += k.countShift
		}
		k.counts++
		k.mu.Unlock()
		_, _ = w.Write([]byte(strconv.Itoa(n)))
	})
	mux.HandleFunc("GET /admin/realms/zanskar/users", func(w http.ResponseWriter, r *http.Request) {
		if !authorised(w, r) {
			return
		}
		first, _ := strconv.Atoi(r.URL.Query().Get("first"))
		size, _ := strconv.Atoi(r.URL.Query().Get("max"))
		if r.URL.Query().Get("briefRepresentation") != "true" || size <= 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		k.mu.Lock()
		defer k.mu.Unlock()
		if k.pageBytes > 0 {
			_, _ = w.Write([]byte(`[{"id":"` + strings.Repeat("x", k.pageBytes) + `"}]`))
			return
		}
		end := min(first+size, len(k.users))
		page := []keycloakUser{}
		if first < len(k.users) {
			page = k.users[first:end]
		}
		_ = json.NewEncoder(w).Encode(page)
	})
	k.srv = httptest.NewTLSServer(mux)
	t.Cleanup(k.srv.Close)
	return k
}

func (k *fakeKeycloak) provider(mutate func(*idp.OIDCConfig)) *idp.Opened {
	cfg := &idp.OIDCConfig{Issuer: k.srv.URL + "/realms/zanskar", ClientID: "zanskar", ClientSecret: "s", UsernameClaim: "preferred_username"}
	if mutate != nil {
		mutate(cfg)
	}
	return &idp.Opened{Provider: idp.Provider{ID: "p1", Name: "kc", Type: idp.TypeOIDC, Enabled: true}, Config: idp.Config{OIDC: cfg, SyncUsers: true}}
}

func person(id, username string) keycloakUser {
	return keycloakUser{ID: id, Username: username, Email: username + "@corp.example", EmailVerified: true, FirstName: strings.ToUpper(username[:1]) + username[1:], LastName: "Test", Enabled: true}
}

// TestKeycloakDirectoryLists (ADR 0035): every page is read; disabled
// users and service accounts are left out; each person is asserted as
// their sign-in would be: the id as subject, the username, the verified
// address, and the name Keycloak's own name claim gives.
func TestKeycloakDirectoryLists(t *testing.T) {
	k := newFakeKeycloak(t)
	off := person("u4", "dora")
	off.Enabled = false
	sa := person("u5", "service-account-zanskar")
	sa.ServiceAccountClientID = "zanskar"
	firstOnly := person("u6", "finn")
	firstOnly.LastName = ""
	k.users = []keycloakUser{person("u1", "alice"), person("u2", "bob"), person("u3", "carol"), off, sa, firstOnly}
	d := &KeycloakDirectory{HTTPClient: k.srv.Client(), PageSize: 2}
	got, err := d.Users(context.Background(), k.provider(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("listed %d: %+v", len(got), got)
	}
	want := idp.Identity{ExternalID: "u1", Username: "alice", DisplayName: "Alice Test", Email: "alice@corp.example"}
	if got[0].ExternalID != want.ExternalID || got[0].Username != want.Username || got[0].DisplayName != want.DisplayName || got[0].Email != want.Email {
		t.Fatalf("alice: %+v", got[0])
	}
	if got[3].Username != "finn" || got[3].DisplayName != "Finn" {
		t.Fatalf("finn: %+v", got[3])
	}

	// The username claim is honoured as the sign-in honours it.
	got, err = d.Users(context.Background(), k.provider(func(c *idp.OIDCConfig) { c.UsernameClaim = "sub" }))
	if err != nil || got[0].Username != "u1" {
		t.Fatalf("sub as username: %+v %v", got, err)
	}
}

// TestKeycloakDirectoryAppliesTheDomainGate: with allowed domains, a person
// whose address is unverified or elsewhere would be refused at sign-in, so
// the listing leaves them out as if not in the realm.
func TestKeycloakDirectoryAppliesTheDomainGate(t *testing.T) {
	k := newFakeKeycloak(t)
	unverified := person("u2", "bob")
	unverified.EmailVerified = false
	elsewhere := person("u3", "carol")
	elsewhere.Email = "carol@else.example"
	k.users = []keycloakUser{person("u1", "alice"), unverified, elsewhere}
	d := &KeycloakDirectory{HTTPClient: k.srv.Client()}
	got, err := d.Users(context.Background(), k.provider(func(c *idp.OIDCConfig) { c.AllowedDomains = []string{"corp.example"} }))
	if err != nil || len(got) != 1 || got[0].Username != "alice" {
		t.Fatalf("got %+v %v", got, err)
	}
}

// TestKeycloakDirectoryRefusesAnIncompleteList: anything that may leave
// someone out is an error, never a shorter list: a refusal (naming the role
// to grant), wrong client credentials, a realm that changed while it was
// read, a count the pages do not reach, an answer too large, and an issuer
// that is not a Keycloak realm.
func TestKeycloakDirectoryRefusesAnIncompleteList(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(k *fakeKeycloak)
		mutate func(c *idp.OIDCConfig)
		want   string
	}{
		{"forbidden", func(k *fakeKeycloak) { k.status = http.StatusForbidden }, nil, "view-users"},
		{"server error", func(k *fakeKeycloak) { k.status = http.StatusInternalServerError }, nil, "HTTP 500"},
		{"wrong secret", nil, func(c *idp.OIDCConfig) { c.ClientSecret = "nope" }, "unauthorized_client"},
		{"realm changing", func(k *fakeKeycloak) { k.countShift = 1 }, nil, "changed while they were listed"},
		{"count beyond the pages", func(k *fakeKeycloak) { k.extraCount = 1 }, nil, "counts 2 users but listed 1"},
		{"answer too large", func(k *fakeKeycloak) { k.pageBytes = maxPageBytes + 1 }, nil, "too large"},
		{"not a realm", nil, func(c *idp.OIDCConfig) { c.Issuer = strings.Replace(c.Issuer, "/realms/", "/tenants/", 1) }, "not a Keycloak realm"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := newFakeKeycloak(t)
			k.users = []keycloakUser{person("u1", "alice")}
			if tc.setup != nil {
				tc.setup(k)
			}
			got, err := (&KeycloakDirectory{HTTPClient: k.srv.Client()}).Users(context.Background(), k.provider(tc.mutate))
			if err == nil || !strings.Contains(err.Error(), tc.want) || got != nil {
				t.Fatalf("got %v %v, want an error with %q", got, err, tc.want)
			}
		})
	}
}
