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
	"maps"
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
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/group"
	"github.com/albatroxxx/zanskar/internal/idp"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
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
		maps.Copy(claims, f.claims)
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
	db := storetest.Open(t)
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
	return driveNext(t, e, f, id, "/admin")
}

// driveNext is drive with the post-login path the browser asks for.
func driveNext(t *testing.T, e *env, f *fakeIdP, id, next string) (status int, location string, cookies []*http.Cookie) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get(e.app.URL + "/api/v1/auth/oidc/" + id + "/start?next=" + url.QueryEscape(next))
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
	f.claims = map[string]any{"preferred_username": "bob", "email": "bob@else.example", "email_verified": true}
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
	e, id := newEnv(t, f, idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s", ZanskarMFA: true}, AutoProvision: true})
	e.h.MFAEnrolled = func(context.Context, string) (bool, error) { return true, nil }
	status, location, cookies := drive(t, e, f, id)
	if status != 302 || !strings.HasPrefix(location, "/login?next=") || !hasSession(cookies) {
		t.Fatalf("expected partial session redirect to login: %d %s", status, location)
	}
	// Without zanskar_mfa the provider's sign-in is the second factor.
	e.h.cache = sync.Map{}
	e2, id2 := newEnv(t, f, idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s"}, AutoProvision: true})
	e2.h.MFAEnrolled = func(context.Context, string) (bool, error) { return true, nil }
	if _, location2, _ := drive(t, e2, f, id2); location2 != "/admin" {
		t.Fatalf("the provider's MFA should complete the session: %s", location2)
	}
}

// TestProviderOwnsMFAByDefault (ADR 0035): a provider sign-in asks for no
// Zanskar authenticator, neither a code from one already enrolled nor an
// enrolment when the deployment requires MFA. The requirement is for local
// and directory (LDAP) accounts; the provider enforces its own.
func TestProviderOwnsMFAByDefault(t *testing.T) {
	f := newFakeIdP(t)
	f.claims = map[string]any{"preferred_username": "erin", "email": "erin@corp.example"}
	e, id := newEnv(t, f, idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s"}, AutoProvision: true})
	e.h.RequireMFA = func() bool { return true }
	for _, enrolled := range []bool{false, true} {
		e.h.MFAEnrolled = func(context.Context, string) (bool, error) { return enrolled, nil }
		status, location, cookies := drive(t, e, f, id)
		if status != 302 || location != "/admin" || !hasSession(cookies) {
			t.Fatalf("enrolled=%v: want a complete sign-in, got %d %s", enrolled, status, location)
		}
	}
	events, _, err := e.h.Audit.List(context.Background(), audit.Filter{Action: audit.UserLogin, Limit: 10})
	if err != nil || len(events) != 2 {
		t.Fatalf("login events: %d %v", len(events), err)
	}
	for _, ev := range events {
		var d map[string]string
		_ = json.Unmarshal(ev.Details, &d)
		if d["stage"] != "complete" || d["mfa"] != "provider" {
			t.Fatalf("login event %v: want stage complete, mfa provider", d)
		}
	}

	// With zanskar_mfa and MFA required, a person with no authenticator is
	// sent to enrol one, as before.
	e2, id2 := newEnv(t, f, idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s", ZanskarMFA: true}, AutoProvision: true})
	e2.h.RequireMFA = func() bool { return true }
	if _, loc, _ := drive(t, e2, f, id2); !strings.HasPrefix(loc, "/login?next=") {
		t.Fatalf("zanskar_mfa with MFA required: want the enrolment step, got %s", loc)
	}
}

// TestSkipMFASealedBeforeReadsAsProviderMFA: a configuration sealed with
// the old skip_mfa field, whatever its value, reads as the provider owning
// MFA, so an upgrade needs no edit to every provider.
func TestSkipMFASealedBeforeReadsAsProviderMFA(t *testing.T) {
	for _, raw := range []string{`{"oidc":{"issuer":"https://x","skip_mfa":false}}`, `{"oidc":{"issuer":"https://x","skip_mfa":true}}`} {
		var c idp.Config
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatal(err)
		}
		if c.OIDC.ZanskarMFA {
			t.Fatalf("%s: read as zanskar_mfa", raw)
		}
	}
}

// TestPartialSignInKeepsTheFailureCount: wrong passwords and wrong
// authenticator codes share one budget per account (M7). A provider sign-in
// that still owes the code is not a complete sign-in, so it must leave the
// account's failure count alone, or each one would hand out a fresh set of
// guesses at the code; one that completes clears it.
func TestPartialSignInKeepsTheFailureCount(t *testing.T) {
	f := newFakeIdP(t)
	f.claims = map[string]any{"preferred_username": "dora", "email": "dora@corp.example"}
	e, id := newEnv(t, f, idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s", ZanskarMFA: true}, AutoProvision: true})
	if st, _, _ := drive(t, e, f, id); st != 302 {
		t.Fatalf("first sign-in: %d", st)
	}
	ctx := context.Background()
	u, err := e.users.GetByUsername(ctx, "dora")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := e.users.RecordLoginFailure(ctx, u.ID, 5, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	failed := func() int {
		t.Helper()
		got, err := e.users.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.FailedLogins
	}

	e.h.MFAEnrolled = func(context.Context, string) (bool, error) { return true, nil }
	if st, loc, _ := drive(t, e, f, id); st != 302 || !strings.HasPrefix(loc, "/login?next=") {
		t.Fatalf("sign-in owing the code: %d %s", st, loc)
	}
	if n := failed(); n != 2 {
		t.Fatalf("a provider sign-in with the code still owed left %d failures on the account, want 2", n)
	}
	e.h.MFAEnrolled = func(context.Context, string) (bool, error) { return false, nil }
	if st, loc, _ := drive(t, e, f, id); st != 302 || loc != "/admin" {
		t.Fatalf("complete sign-in: %d %s", st, loc)
	}
	if n := failed(); n != 0 {
		t.Fatalf("a complete provider sign-in left %d failures, want 0", n)
	}
}

// TestSafeNext: the post-login path is used in a Location header, so it must
// be a path on this origin after a browser has had its way with it.
func TestSafeNext(t *testing.T) {
	for _, tc := range []struct {
		next string
		ok   bool
		why  string
	}{
		{"/ok", true, "a plain path"},
		{"/ok?x=1", true, "a query string is fine"},
		{"/ok/", true, "a single trailing slash is fine"},
		{"/", true, "the root"},
		{"/admin/sessions?tab=live#x", true, "a fragment is fine"},
		{"/café", true, "non-ASCII is percent-encoded by http.Redirect"},
		// A percent-encoded control character in the path is harmless: the
		// browser keeps it encoded, so it can never become a second "/". The
		// literal string only arises from double encoding ("%2509" in the
		// query); a single "%09" reaches safeNext as a real tab and is refused.
		{"/%09/evil.example", true, "percent-encoded tab stays encoded"},
		{"", false, "empty"},
		{"/\t/evil.example", false, "tab: browsers strip it, leaving //evil.example"},
		{"/\r/evil.example", false, "carriage return"},
		{"/\n/evil.example", false, "line feed"},
		{"/ok\x00", false, "NUL"},
		{"/ok\x7f", false, "DEL"},
		{"/ok\x1b", false, "escape"},
		{"/\\evil.example", false, "backslash reads as a slash in http URLs"},
		{"//evil.example", false, "scheme-relative"},
		{"///evil.example", false, "browsers skip the extra slashes"},
		{"http://evil.example", false, "absolute URL"},
		{"https://evil.example/", false, "absolute URL"},
		{"javascript:alert(1)", false, "a scheme"},
		{"evil.example", false, "no leading slash"},
		{"ok", false, "relative path"},
		{"?x=1", false, "no path"},
		{"/ok/../../x", false, "dot-dot segments"},
		{"/ok/./x", false, "dot segment"},
		{"/ok//x", false, "not clean"},
		{"/ok/%2e%2e/x", false, "percent-encoded dot-dot: browsers treat it as .."},
		{"/@evil.example", true, "an @ in a path is just an @"},
	} {
		if got := safeNext(tc.next); got != tc.ok {
			t.Errorf("safeNext(%q) = %v, want %v (%s)", tc.next, got, tc.ok, tc.why)
		}
	}
}

// TestCallbackRefusesControlCharacterNext reproduces H3 end to end: a next of
// "/" + TAB + "/evil.example" used to be accepted, sealed into the state
// cookie and written verbatim into the callback's Location, where a browser
// drops the tab and goes to //evil.example. Now it is refused at start and
// the sign-in lands on "/".
func TestCallbackRefusesControlCharacterNext(t *testing.T) {
	f := newFakeIdP(t)
	f.claims = map[string]any{"preferred_username": "dave", "email": "dave@corp.example"}
	e, id := newEnv(t, f, idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s"}, AutoProvision: true})
	for _, next := range []string{"/\t/evil.example", "/\r\n/evil.example", "//evil.example", "/\\evil.example", "https://evil.example/"} {
		status, location, cookies := driveNext(t, e, f, id, next)
		if status != 302 || location != "/" || !hasSession(cookies) {
			t.Fatalf("next=%q: callback answered %d Location %q (session cookie %v); want a 302 to /", next, status, location, hasSession(cookies))
		}
	}
	// And a good path still gets the user where they were going.
	if status, location, _ := driveNext(t, e, f, id, "/targets?tab=live"); status != 302 || location != "/targets?tab=live" {
		t.Fatalf("a plain path must be kept: %d %q", status, location)
	}
}

// linkEvents returns the user.link events recorded so far.
func linkEvents(t *testing.T, e *env) []audit.Event {
	t.Helper()
	evs, _, err := e.h.Audit.List(context.Background(), audit.Filter{Action: "user.link", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// TestFlowAdoptsPreCreatedAccount is H8 through a real OIDC sign-in. An
// account an administrator created with no password, under the username the
// provider asserts, signs in with auto-provisioning off: the callback links
// it to the provider and the subject, records the link as user.link, and the
// account keeps the roles it was given. The second sign-in matches on the
// subject and links nothing.
func TestFlowAdoptsPreCreatedAccount(t *testing.T) {
	f := newFakeIdP(t)
	f.claims = map[string]any{"preferred_username": "erin", "email": "erin@corp.example", "name": "Erin E"}
	e, id := newEnv(t, f, idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s"}, AutoProvision: false})
	ctx := context.Background()
	erin := &user.User{Username: "erin", DisplayName: "Erin", Roles: []user.Role{user.RoleAuditor}}
	if err := e.users.Create(ctx, erin); err != nil {
		t.Fatal(err)
	}

	status, location, cookies := drive(t, e, f, id)
	if status != 302 || location != "/admin" || !hasSession(cookies) {
		t.Fatalf("callback: %d %s session=%v", status, location, hasSession(cookies))
	}
	got, err := e.users.GetByID(ctx, erin.ID)
	if err != nil || got.IdPID != id || got.ExternalID != "sub-1" || len(got.Roles) != 1 || got.Roles[0] != user.RoleAuditor {
		t.Fatalf("pre-created account after sign-in: %+v %v", got, err)
	}
	evs := linkEvents(t, e)
	if len(evs) != 1 {
		t.Fatalf("%d user.link events, want 1", len(evs))
	}
	var d map[string]string
	_ = json.Unmarshal(evs[0].Details, &d)
	if ev := evs[0]; ev.ActorUserID != erin.ID || ev.ObjectID != erin.ID || ev.Outcome != audit.Success || ev.ActorIP == "" ||
		d["idp"] != id || d["idp_name"] != "fake" || d["external_id"] != "sub-1" {
		t.Fatalf("user.link event: %+v %v", ev, d)
	}

	if status, _, _ := drive(t, e, f, id); status != 302 {
		t.Fatalf("second sign-in: %d", status)
	}
	if n := len(linkEvents(t, e)); n != 1 {
		t.Fatalf("%d user.link events after the second sign-in, want still 1", n)
	}
	if all, _, _ := e.users.List(ctx, "", 10); len(all) != 1 {
		t.Fatalf("%d accounts, want 1", len(all))
	}
}

// TestFlowRefusesLocalPasswordAccount: a provider asserting the username of a
// local account that has a password is refused, with a reason the sign-in
// page and the audit log both show, and the account is left unlinked.
func TestFlowRefusesLocalPasswordAccount(t *testing.T) {
	for _, auto := range []bool{false, true} {
		f := newFakeIdP(t)
		f.claims = map[string]any{"preferred_username": "frank", "email": "frank@corp.example"}
		e, id := newEnv(t, f, idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s"}, AutoProvision: auto})
		ctx := context.Background()
		frank := &user.User{Username: "frank", DisplayName: "Frank", Roles: []user.Role{user.RoleAdmin},
			PasswordHash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
		if err := e.users.Create(ctx, frank); err != nil {
			t.Fatal(err)
		}

		status, location, cookies := drive(t, e, f, id)
		if status != 302 || location != "/login?error=account_conflict" || hasSession(cookies) {
			t.Fatalf("auto_provision=%v: callback %d %s session=%v, want a refusal", auto, status, location, hasSession(cookies))
		}
		if got, _ := e.users.GetByID(ctx, frank.ID); got.IdPID != "" || got.ExternalID != "" {
			t.Fatalf("auto_provision=%v: the password account was linked to %q/%q", auto, got.IdPID, got.ExternalID)
		}
		evs, _, _ := e.h.Audit.List(ctx, audit.Filter{Action: "user.login", Limit: 1})
		var d map[string]string
		if len(evs) == 1 {
			_ = json.Unmarshal(evs[0].Details, &d)
		}
		if len(evs) != 1 || evs[0].Outcome != audit.Failure || d["reason"] != "account_conflict" {
			t.Fatalf("auto_provision=%v: user.login audit %v %v", auto, evs, d)
		}
		if n := len(linkEvents(t, e)); n != 0 {
			t.Fatalf("auto_provision=%v: %d user.link events, want none", auto, n)
		}
	}
}

// TestStartUsesThePublicURL: behind a proxy that terminates TLS the gateway
// sees plain HTTP, so the redirect URI it sends the provider is built from
// ZANSKAR_PUBLIC_URL (BaseURL), never from the request's scheme and host.
func TestStartUsesThePublicURL(t *testing.T) {
	f := newFakeIdP(t)
	e, id := newEnv(t, f, idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s"}, AutoProvision: true, DefaultRoles: []user.Role{user.RoleUser}})
	e.h.BaseURL = "https://gw.example.com"
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get(e.app.URL + "/api/v1/auth/oidc/" + id + "/start")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil || res.StatusCode != http.StatusFound {
		t.Fatalf("start: %d %v", res.StatusCode, err)
	}
	if got, want := loc.Query().Get("redirect_uri"), "https://gw.example.com/api/v1/auth/oidc/"+id+"/callback"; got != want {
		t.Fatalf("redirect_uri %q, want %q", got, want)
	}
}

// TestDomainGateNeedsAVerifiedEmail: allowed_domains was checked against the
// email claim whatever the provider said about it (L12), so on a provider
// where people edit their own address anyone could pass the gate. The email
// must now be verified (email_verified true, as a boolean or the string some
// providers send), unless the provider is marked trust_email, for one that
// never sends the claim (Entra ID) and whose addresses its directory owns.
// An address the provider says is unverified is not used at all, not even to
// make a username.
func TestDomainGateNeedsAVerifiedEmail(t *testing.T) {
	for _, c := range []struct {
		name   string
		claims map[string]any
		trust  bool
		want   string // "" signs in
	}{
		{"verified", map[string]any{"preferred_username": "ann", "email": "ann@corp.example", "email_verified": true}, false, ""},
		{"verified as a string", map[string]any{"preferred_username": "ann", "email": "ann@corp.example", "email_verified": "true"}, false, ""},
		{"unverified", map[string]any{"preferred_username": "ann", "email": "ann@corp.example", "email_verified": false}, false, "email_unverified"},
		{"unverified as a string", map[string]any{"preferred_username": "ann", "email": "ann@corp.example", "email_verified": "false"}, false, "email_unverified"},
		{"not said", map[string]any{"preferred_username": "ann", "email": "ann@corp.example"}, false, "email_unverified"},
		{"not said, provider trusted", map[string]any{"preferred_username": "ann", "email": "ann@corp.example"}, true, ""},
		{"unverified, provider trusted", map[string]any{"preferred_username": "ann", "email": "ann@corp.example", "email_verified": false}, true, "email_unverified"},
		{"verified, other domain", map[string]any{"preferred_username": "ann", "email": "ann@else.example", "email_verified": true}, false, "domain_not_allowed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeIdP(t)
			f.claims = c.claims
			e, id := newEnv(t, f, idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s", AllowedDomains: []string{"corp.example"}, TrustEmail: c.trust}, AutoProvision: true})
			status, location, cookies := drive(t, e, f, id)
			if c.want == "" {
				if status != 302 || strings.Contains(location, "error=") || !hasSession(cookies) {
					t.Fatalf("want a sign-in, got %d %s", status, location)
				}
				return
			}
			if status != 302 || !strings.Contains(location, "error="+c.want) || hasSession(cookies) {
				t.Fatalf("want error=%s, got %d %s", c.want, status, location)
			}
		})
	}
}

// TestUnverifiedEmailMakesNoUsername: with no username claim the username
// falls back to the email's local part, and a pre-created account with that
// name is adopted (H8). An address the provider has not verified must not
// name the account, or whoever typed it in would sign in as someone else.
func TestUnverifiedEmailMakesNoUsername(t *testing.T) {
	for _, verified := range []any{false, nil} {
		f := newFakeIdP(t)
		f.claims = map[string]any{"email": "carol@corp.example"}
		if verified != nil {
			f.claims["email_verified"] = verified
		}
		e, id := newEnv(t, f, idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s"}, AutoProvision: true})
		status, location, cookies := drive(t, e, f, id)
		if status != 302 || !strings.Contains(location, "error=claims_invalid") || hasSession(cookies) {
			t.Fatalf("email_verified %v: got %d %s, want claims_invalid", verified, status, location)
		}
		if _, err := e.users.GetByUsername(context.Background(), "carol"); err == nil {
			t.Fatalf("email_verified %v: an account was named after an unverified address", verified)
		}
	}
}

// TestStateCookieUnderSecureCookies: where cookies are Secure the state
// cookie is __Host- prefixed on Path=/, so a sibling subdomain cannot plant
// a sealed state of its own and finish its authorization code in this
// browser; the callback reads that name (S1 L6).
func TestStateCookieUnderSecureCookies(t *testing.T) {
	f := newFakeIdP(t)
	e, id := newEnv(t, f, idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s"}, AutoProvision: true})
	e.h.Sessions.SecureCookie = true
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get(e.app.URL + "/api/v1/auth/oidc/" + id + "/start")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 302 {
		t.Fatalf("start: %d", res.StatusCode)
	}
	var state *http.Cookie
	for _, c := range res.Cookies() {
		if strings.Contains(c.Name, "zanskar_oidc") {
			state = c
		}
	}
	if state == nil || state.Name != "__Host-zanskar_oidc" || state.Path != "/" || !state.Secure || !state.HttpOnly {
		t.Fatalf("state cookie: %+v", state)
	}
	// The callback looks for the prefixed name: with the bare one it sees no state.
	req, _ := http.NewRequest("GET", e.app.URL+"/api/v1/auth/oidc/"+id+"/callback?state=x&code=y", nil)
	req.AddCookie(&http.Cookie{Name: "zanskar_oidc", Value: state.Value})
	res2, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	if loc := res2.Header.Get("Location"); res2.StatusCode != 302 || !strings.Contains(loc, "error=state_missing") {
		t.Fatalf("callback with the bare cookie name: %d %s", res2.StatusCode, loc)
	}
	req, _ = http.NewRequest("GET", e.app.URL+"/api/v1/auth/oidc/"+id+"/callback?state=x&code=y", nil)
	req.AddCookie(&http.Cookie{Name: state.Name, Value: state.Value})
	res3, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res3.Body.Close()
	if loc := res3.Header.Get("Location"); res3.StatusCode != 302 || !strings.Contains(loc, "error=state_invalid") {
		t.Fatalf("callback with the prefixed cookie and a wrong state: %d %s", res3.StatusCode, loc)
	}
}
