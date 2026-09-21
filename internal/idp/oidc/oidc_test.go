// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/group"
	"github.com/albatroxxx/zanskar/internal/idp"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// fakeIdP is a minimal OpenID provider: discovery, JWKS, authorize (which
// immediately redirects back with a code) and token (which mints an id_token).
type fakeIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	claims map[string]any // extra claims for the next id_token
	nonce  string
	codes  map[string]bool
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, codes: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.nonce = q.Get("nonce")
		code := "code-" + q.Get("state")
		f.codes[code] = true
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if !f.codes[r.Form.Get("code")] {
			http.Error(w, "bad code", 400)
			return
		}
		claims := map[string]any{"iss": f.srv.URL, "aud": "cid", "sub": "sub-1", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": f.nonce}
		for k, v := range f.claims {
			claims[k] = v
		}
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
		payload, _ := json.Marshal(claims)
		obj, _ := signer.Sign(payload)
		tok, _ := obj.CompactSerialize()
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": tok})
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

type env struct {
	app     *httptest.Server
	users   *user.Repo
	groups  *group.Repo
	repo    *idp.Repo
	h       *Handler
	groupID string
}

func newEnv(t *testing.T, f *fakeIdP, cfg idp.Config) (*env, string) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	kek, _ := crypto.NewLocalKEK(bytes.Repeat([]byte{7}, 32))
	ring, err := keyring.Open(ctx, db, kek)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := &env{users: user.NewRepo(db), groups: group.NewRepo(db), repo: idp.NewRepo(db, ring)}
	g := &group.Group{Name: "ops"}
	if err := e.groups.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	e.groupID = g.ID
	if cfg.GroupMapping != nil {
		cfg.GroupMapping = idp.GroupMapping{"ops-team": g.ID}
	}
	cfg.OIDC.Issuer = f.srv.URL
	p := &idp.Provider{Name: "fake", Type: idp.TypeOIDC, Enabled: true}
	if err := e.repo.Create(ctx, p, &cfg); err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{2}, 32), false)
	e.h = &Handler{
		Providers: e.repo, Provisioner: &idp.Provisioner{Users: e.users, Groups: e.groups}, Sessions: sessions,
		Audit: audit.NewLog(db), Log: log, StateKey: bytes.Repeat([]byte{5}, 32), HTTPClient: f.srv.Client(),
		MFAEnrolled: func(context.Context, string) (bool, error) { return false, nil },
	}
	mux := http.NewServeMux()
	e.h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: e.users, Log: log}
	e.app = httptest.NewServer(mw.Authenticate(mux))
	t.Cleanup(e.app.Close)
	return e, p.ID
}

// drive follows start -> provider -> callback manually so we can inspect each hop.
func drive(t *testing.T, e *env, f *fakeIdP, id string) (status int, location string, cookies []*http.Cookie) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get(e.app.URL + "/api/v1/auth/oidc/" + id + "/start?next=/admin")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 302 {
		t.Fatalf("start: %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.HasPrefix(loc, f.srv.URL+"/authorize") || !strings.Contains(loc, "code_challenge_method=S256") {
		t.Fatalf("start redirect: %s", loc)
	}
	// Ask the provider directly (it does not need cookies).
	pres, err := f.srv.Client().Transport.RoundTrip(mustReq(t, loc))
	if err != nil {
		t.Fatal(err)
	}
	pres.Body.Close()
	cb := pres.Header.Get("Location")
	res, err = client.Get(cb)
	if err != nil {
		t.Fatal(err)
	}
	status = res.StatusCode
	location = res.Header.Get("Location")
	_ = res.Body.Close()
	u, _ := url.Parse(e.app.URL)
	return status, location, jar.Cookies(u)
}

func mustReq(t *testing.T, u string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func hasSession(cs []*http.Cookie) bool {
	for _, c := range cs {
		if c.Name == auth.CookieName && c.Value != "" {
			return true
		}
	}
	return false
}

func TestFlowProvisionsAndMapsGroups(t *testing.T) {
	f := newFakeIdP(t)
	f.claims = map[string]any{"preferred_username": "Alice", "email": "alice@corp.example", "name": "Alice A", "groups": []string{"ops-team", "other"}}
	e, id := newEnv(t, f, idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s", GroupsClaim: "groups"}, AutoProvision: true, GroupMapping: idp.GroupMapping{}, DefaultRoles: []user.Role{user.RoleUser}})
	status, location, cookies := drive(t, e, f, id)
	if status != 302 || location != "/admin" || !hasSession(cookies) {
		t.Fatalf("callback: %d %s cookies=%v", status, location, cookies)
	}
	u, err := e.users.GetByUsername(context.Background(), "alice")
	if err != nil || u.IdPID != id || u.ExternalID != "sub-1" || u.Email != "alice@corp.example" || !u.HasRole(user.RoleUser) || u.HasRole(user.RoleAdmin) {
		t.Fatalf("provisioned user: %+v %v", u, err)
	}
	members, err := e.groups.Members(context.Background(), e.groupID)
	if err != nil || len(members) != 1 || members[0].UserID != u.ID {
		t.Fatalf("group mapping: %v %v", members, err)
	}
	// Second login with the group gone removes membership.
	f.claims["groups"] = []string{"other"}
	if st, _, _ := drive(t, e, f, id); st != 302 {
		t.Fatalf("second login: %d", st)
	}
	if members, _ := e.groups.Members(context.Background(), e.groupID); len(members) != 0 {
		t.Fatalf("expected membership removed, got %v", members)
	}
	// Public provider list.
	pres, _ := http.Get(e.app.URL + "/api/v1/auth/providers")
	var page map[string]any
	_ = json.NewDecoder(pres.Body).Decode(&page)
	pres.Body.Close()
	if items := page["items"].([]any); len(items) != 1 || items[0].(map[string]any)["name"] != "fake" {
		t.Fatalf("providers: %v", page)
	}
}

func TestDomainAndStateChecks(t *testing.T) {
	f := newFakeIdP(t)
	f.claims = map[string]any{"preferred_username": "bob", "email": "bob@else.example"}
	e, id := newEnv(t, f, idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s", AllowedDomains: []string{"corp.example"}}, AutoProvision: true})
	status, location, cookies := drive(t, e, f, id)
	if status != 302 || !strings.Contains(location, "error=domain_not_allowed") || hasSession(cookies) {
		t.Fatalf("domain check: %d %s", status, location)
	}
	if _, err := e.users.GetByUsername(context.Background(), "bob"); err == nil {
		t.Fatal("user must not be provisioned when domain is rejected")
	}

	// Tampered state: callback with a state that does not match the cookie.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r1, _ := client.Get(e.app.URL + "/api/v1/auth/oidc/" + id + "/start")
	r1.Body.Close()
	r2, _ := client.Get(e.app.URL + "/api/v1/auth/oidc/" + id + "/callback?code=x&state=forged")
	r2.Body.Close()
	if r2.StatusCode != 302 || !strings.Contains(r2.Header.Get("Location"), "error=state_invalid") {
		t.Fatalf("tampered state: %d %s", r2.StatusCode, r2.Header.Get("Location"))
	}
	// No cookie at all.
	r3, _ := http.Get(e.app.URL + "/api/v1/auth/oidc/" + id + "/callback?code=x&state=y")
	r3.Body.Close()
	if !strings.Contains(r3.Request.URL.String()+r3.Header.Get("Location"), "error=state_missing") && r3.StatusCode != 200 {
		t.Fatalf("missing state: %d", r3.StatusCode)
	}
}

func TestPartialSessionWhenEnrolled(t *testing.T) {
	f := newFakeIdP(t)
	f.claims = map[string]any{"preferred_username": "carol", "email": "carol@corp.example"}
	e, id := newEnv(t, f, idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s"}, AutoProvision: true})
	e.h.MFAEnrolled = func(context.Context, string) (bool, error) { return true, nil }
	status, location, cookies := drive(t, e, f, id)
	if status != 302 || !strings.HasPrefix(location, "/login?next=") || !hasSession(cookies) {
		t.Fatalf("expected partial session redirect to login: %d %s", status, location)
	}
	// SkipMFA trusts the provider.
	e.h.cache = sync.Map{}
	e2, id2 := newEnv(t, f, idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s", SkipMFA: true}, AutoProvision: true})
	e2.h.MFAEnrolled = func(context.Context, string) (bool, error) { return true, nil }
	if _, location2, _ := drive(t, e2, f, id2); location2 != "/admin" {
		t.Fatalf("skip_mfa should complete the session: %s", location2)
	}
}
