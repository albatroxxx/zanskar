// SPDX-License-Identifier: Apache-2.0

package apitoken

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/group"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/user"
)

// 2026-11-03, idea 10 (ADR 0044): an administrator's token for automation,
// the Terraform provider and pipelines, scoped to the configuration API.

func TestRepoOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		users := user.NewRepo(db)
		u := &user.User{Username: "root", DisplayName: "Root", Roles: []user.Role{user.RoleAdmin}}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		now := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
		r := NewRepo(db)
		r.now = func() time.Time { return now }
		tok, secret, err := r.Create(ctx, u.ID, "terraform", 48*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(secret, auth.TokenPrefix) || len(secret) < 40 || tok.Prefix != secret[:prefixLen] {
			t.Fatalf("secret %q prefix %q", secret, tok.Prefix)
		}
		var stored string
		if err := db.QueryRowContext(ctx, db.Rebind(`SELECT token_hash FROM api_tokens WHERE id = ?`), tok.ID).Scan(&stored); err != nil || stored == secret || strings.Contains(stored, secret[len(auth.TokenPrefix):]) {
			t.Fatalf("the secret is kept only as its hash: %q %v", stored, err)
		}
		uid, tid, err := r.Authenticate(ctx, secret, "203.0.113.1")
		if err != nil || uid != u.ID || tid != tok.ID {
			t.Fatalf("authenticate: %q %q %v", uid, tid, err)
		}
		if _, _, err := r.Authenticate(ctx, secret+"x", ""); !errors.Is(err, auth.ErrBadToken) {
			t.Fatalf("a wrong token: %v", err)
		}
		// Last use, written once a minute however often the token is used.
		got, _ := r.Get(ctx, tok.ID)
		if got.LastUsedAt == nil || !got.LastUsedAt.Equal(now) || got.Username != "root" {
			t.Fatalf("last use: %+v", got)
		}
		now = now.Add(30 * time.Second)
		_, _, _ = r.Authenticate(ctx, secret, "")
		if got, _ = r.Get(ctx, tok.ID); !got.LastUsedAt.Equal(now.Add(-30 * time.Second)) {
			t.Fatalf("written again within the minute: %v", got.LastUsedAt)
		}
		now = now.Add(31 * time.Second)
		_, _, _ = r.Authenticate(ctx, secret, "")
		if got, _ = r.Get(ctx, tok.ID); !got.LastUsedAt.Equal(now) {
			t.Fatalf("not written after the minute: %v", got.LastUsedAt)
		}
		if n, _ := r.CountActive(ctx, u.ID); n != 1 {
			t.Fatalf("active: %d", n)
		}
		// Expired: refused, and no longer counted.
		now = now.Add(48 * time.Hour)
		if _, _, err := r.Authenticate(ctx, secret, ""); !errors.Is(err, auth.ErrBadToken) {
			t.Fatalf("an expired token: %v", err)
		}
		if n, _ := r.CountActive(ctx, u.ID); n != 0 {
			t.Fatalf("an expired token counted: %d", n)
		}
		// Revoked: refused, its first revocation kept.
		now = now.Add(-47 * time.Hour)
		first, err := r.Revoke(ctx, tok.ID)
		if err != nil || first.RevokedAt == nil {
			t.Fatal(first, err)
		}
		if _, _, err := r.Authenticate(ctx, secret, ""); !errors.Is(err, auth.ErrBadToken) {
			t.Fatalf("a revoked token: %v", err)
		}
		now = now.Add(time.Hour)
		again, _ := r.Revoke(ctx, tok.ID)
		if !again.RevokedAt.Equal(*first.RevokedAt) {
			t.Fatal("a second revoke moved the time")
		}
		if _, err := r.Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unknown: %v", err)
		}
		list, err := r.List(ctx)
		if err != nil || len(list) != 1 {
			t.Fatalf("list: %v %v", list, err)
		}
		// The token goes with its owner.
		if _, err := db.ExecContext(ctx, db.Rebind(`DELETE FROM users WHERE id = ?`), u.ID); err != nil {
			t.Fatal(err)
		}
		if list, _ := r.List(ctx); len(list) != 0 {
			t.Fatalf("a deleted owner's token stays: %v", list)
		}
	})
}

type env struct {
	srv      http.Handler
	repo     *Repo
	users    *user.Repo
	sessions *auth.Sessions
	audit    *audit.Log
	h        *Handler
	admin    *http.Cookie
	csrf     string
	adminID  string
	sessID   string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	db := storetest.Open(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := &env{repo: NewRepo(db), users: user.NewRepo(db), audit: audit.NewLog(db)}
	e.sessions = auth.NewSessions(db, bytes.Repeat([]byte{4}, 32), false)
	e.h = &Handler{Repo: e.repo, Audit: e.audit, Log: log, MFAEnrolled: func(context.Context, string) (bool, error) { return false, nil }}
	mux := http.NewServeMux()
	e.h.Register(mux)
	(&group.AdminHandler{Groups: group.NewRepo(db), Audit: e.audit, Log: log}).Register(mux)
	mux.Handle("GET /api/v1/auth/me", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := auth.FromContext(r.Context())
		httpx.WriteJSON(w, 200, map[string]string{"username": p.User.Username})
	})))
	mux.Handle("GET /api/v1/admin/settings", auth.RequireRole(user.RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })))
	mw := &auth.Middleware{Sessions: e.sessions, Users: e.users, Log: log, Tokens: e.repo}
	e.srv = mw.Authenticate(mw.CSRF(mux))
	u := &user.User{Username: "root", DisplayName: "Root", Roles: []user.Role{user.RoleAdmin}}
	if err := e.users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	tok, sess, err := e.sessions.Create(ctx, u.ID, "203.0.113.9", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	e.admin, e.csrf, e.adminID, e.sessID = &http.Cookie{Name: auth.CookieName, Value: tok}, e.sessions.CSRFToken(sess.ID), u.ID, sess.ID
	return e
}

// call sends a request with a cookie (and its CSRF token) or a bearer token.
func (e *env) call(method, path string, body any, cookie *http.Cookie, bearer string) (int, map[string]any) {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.9:4321"
	if cookie != nil {
		req.AddCookie(cookie)
		req.Header.Set("X-CSRF-Token", e.csrf)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

// make creates a token from the admin's browser session.
func (e *env) make(t *testing.T, name string) (string, string) {
	t.Helper()
	code, out := e.call("POST", "/api/v1/admin/api-tokens", map[string]any{"name": name, "days": 30}, e.admin, "")
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	return out["id"].(string), out["secret"].(string)
}

func TestATokenActsOnTheConfigurationOnly(t *testing.T) {
	e := newEnv(t)
	id, secret := e.make(t, "terraform")

	if code, out := e.call("GET", "/api/v1/auth/me", nil, nil, secret); code != 200 || out["username"] != "root" {
		t.Fatalf("whoami: %d %v", code, out)
	}
	// A change, with no CSRF token, audited as the owner with the token named.
	code, out := e.call("POST", "/api/v1/groups", map[string]any{"name": "ops"}, nil, secret)
	if code != 201 {
		t.Fatalf("create a group: %d %v", code, out)
	}
	evs, _, _ := e.audit.List(context.Background(), audit.Filter{Action: audit.GroupCreate})
	if len(evs) != 1 || evs[0].ActorUserID != e.adminID || !strings.Contains(string(evs[0].Details), `"api_token":"`+id+`"`) {
		t.Fatalf("group.create: %+v", evs)
	}
	// Outside the configuration API, or making tokens: refused.
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v1/admin/api-tokens"},
		{"POST", "/api/v1/admin/api-tokens"},
		{"GET", "/api/v1/admin/settings"},
		{"GET", "/api/v1/access-policies/p1/review"},
		{"POST", "/api/v1/credentials"},
		{"GET", "/ws/terminal"},
	} {
		if code, out := e.call(c.method, c.path, map[string]any{"name": "x"}, nil, secret); code != 403 || out["code"] != "token_scope" {
			t.Fatalf("%s %s: %d %v", c.method, c.path, code, out)
		}
	}
	// A wrong token is refused, never read as the cookie beside it.
	if code, out := e.call("GET", "/api/v1/auth/me", nil, e.admin, secret+"x"); code != 401 || out["code"] != "invalid_token" {
		t.Fatalf("a wrong token with a good cookie: %d %v", code, out)
	}
	// Another kind of bearer (SCIM's) is left to its route.
	if code, out := e.call("GET", "/api/v1/auth/me", nil, nil, "zscim_abc"); code != 401 || out["code"] != "unauthenticated" {
		t.Fatalf("a SCIM token: %d %v", code, out)
	}
}

func TestATokenEndsWithItsOwnersStanding(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	_, secret := e.make(t, "ci")
	// Another administrator, so this one may be demoted.
	if err := e.users.Create(ctx, &user.User{Username: "other", DisplayName: "Other", Roles: []user.Role{user.RoleAdmin}}); err != nil {
		t.Fatal(err)
	}
	// No longer an administrator: refused.
	if err := e.users.SetRoles(ctx, e.adminID, []user.Role{user.RoleUser}); err != nil {
		t.Fatal(err)
	}
	if code, out := e.call("GET", "/api/v1/auth/me", nil, nil, secret); code != 401 || out["code"] != "invalid_token" {
		t.Fatalf("a demoted owner: %d %v", code, out)
	}
	if err := e.users.SetRoles(ctx, e.adminID, []user.Role{user.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.call("GET", "/api/v1/auth/me", nil, nil, secret); code != 200 {
		t.Fatalf("an administrator again: %d", code)
	}
	if err := e.users.Update(ctx, e.adminID, "Root", "", user.StatusDisabled); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.call("GET", "/api/v1/auth/me", nil, nil, secret); code != 401 {
		t.Fatalf("a disabled owner: %d", code)
	}
}

func TestMakingAndRevokingTokens(t *testing.T) {
	e := newEnv(t)
	for _, bad := range []map[string]any{{"name": ""}, {"name": strings.Repeat("n", 101)}, {"name": "x", "days": 366}, {"name": "x", "days": -1}} {
		if code, _ := e.call("POST", "/api/v1/admin/api-tokens", bad, e.admin, ""); code != 400 {
			t.Fatalf("%v: %d", bad, code)
		}
	}
	// The default life is 90 days.
	code, out := e.call("POST", "/api/v1/admin/api-tokens", map[string]any{"name": "default"}, e.admin, "")
	if code != 201 {
		t.Fatalf("default: %d %v", code, out)
	}
	created, _ := time.Parse(time.RFC3339Nano, out["created_at"].(string))
	expires, _ := time.Parse(time.RFC3339Nano, out["expires_at"].(string))
	if d := expires.Sub(created); d != DefaultDays*24*time.Hour {
		t.Fatalf("default life %v", d)
	}
	// The secret is shown once: the list never carries it.
	secret := out["secret"].(string)
	code, list := e.call("GET", "/api/v1/admin/api-tokens", nil, e.admin, "")
	raw, _ := json.Marshal(list)
	if code != 200 || strings.Contains(string(raw), secret) || strings.Contains(string(raw), "secret") {
		t.Fatalf("list: %d %s", code, raw)
	}
	evs, _, _ := e.audit.List(context.Background(), audit.Filter{Action: audit.APITokenCreate})
	if len(evs) != 1 || strings.Contains(string(evs[0].Details), secret) || !strings.Contains(string(evs[0].Details), `"name":"default"`) {
		t.Fatalf("api_token.create: %+v", evs)
	}
	// Revoked, it stops at once; a second revoke records nothing more.
	id := out["id"].(string)
	if code, out := e.call("DELETE", "/api/v1/admin/api-tokens/"+id, nil, e.admin, ""); code != 200 || out["revoked_at"] == nil {
		t.Fatalf("revoke: %d %v", code, out)
	}
	if code, _ := e.call("GET", "/api/v1/auth/me", nil, nil, secret); code != 401 {
		t.Fatalf("a revoked token: %d", code)
	}
	_, _ = e.call("DELETE", "/api/v1/admin/api-tokens/"+id, nil, e.admin, "")
	if evs, _, _ := e.audit.List(context.Background(), audit.Filter{Action: audit.APITokenRevoke}); len(evs) != 1 {
		t.Fatalf("api_token.revoke: %d events", len(evs))
	}
	if code, _ := e.call("DELETE", "/api/v1/admin/api-tokens/nope", nil, e.admin, ""); code != 404 {
		t.Fatalf("unknown: %d", code)
	}
	// At most MaxActive at once.
	for i := 0; i < MaxActive; i++ {
		e.make(t, "t")
	}
	if code, out := e.call("POST", "/api/v1/admin/api-tokens", map[string]any{"name": "one more"}, e.admin, ""); code != 409 || out["code"] != "too_many_tokens" {
		t.Fatalf("over the limit: %d %v", code, out)
	}
}

func TestMakingATokenAsksForARecentCode(t *testing.T) {
	e := newEnv(t)
	e.h.MFAEnrolled = func(context.Context, string) (bool, error) { return true, nil }
	if code, out := e.call("POST", "/api/v1/admin/api-tokens", map[string]any{"name": "x"}, e.admin, ""); code != 403 || out["code"] != "step_up_required" {
		t.Fatalf("without a recent code: %d %v", code, out)
	}
	if err := e.sessions.MarkMFAProved(context.Background(), e.sessID); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.call("POST", "/api/v1/admin/api-tokens", map[string]any{"name": "x"}, e.admin, ""); code != 201 {
		t.Fatalf("with a recent code: %d", code)
	}
	e.h.MFAEnrolled = nil
	if code, _ := e.call("POST", "/api/v1/admin/api-tokens", map[string]any{"name": "y"}, e.admin, ""); code != 201 {
		t.Fatalf("still fresh: %d", code)
	}
}

func TestTokenAllowed(t *testing.T) {
	for _, c := range []struct {
		method, path string
		want         bool
	}{
		{"GET", "/api/v1/auth/me", true},
		{"POST", "/api/v1/auth/me", false},
		{"GET", "/api/v1/groups", true},
		{"DELETE", "/api/v1/groups/g1", true},
		{"PUT", "/api/v1/groups/g1/members", true},
		{"POST", "/api/v1/targets", true},
		{"HEAD", "/api/v1/targets/t1", true},
		{"GET", "/api/v1/access-policies", true},
		{"PUT", "/api/v1/access-policies/p1", true},
		{"POST", "/api/v1/access-policies/p1/review", false},
		{"GET", "/api/v1/access-policies/", false},
		{"GET", "/api/v1/credentials", true},
		{"GET", "/api/v1/credentials/c1", true},
		{"POST", "/api/v1/credentials", false},
		{"POST", "/api/v1/credentials/c1/rotate", false},
		{"GET", "/api/v1/admin/config/export", true},
		{"POST", "/api/v1/admin/config/import", true},
		{"GET", "/api/v1/admin/config/import", false},
		{"GET", "/api/v1/groupsx", false},
		{"GET", "/api/v1/groups/", false},
		{"GET", "/api/v1/admin/api-tokens", false},
		{"GET", "/api/v1/sessions", false},
		{"GET", "/ws/terminal", false},
	} {
		if got := auth.TokenAllowed(c.method, c.path); got != c.want {
			t.Fatalf("%s %s: %v, want %v", c.method, c.path, got, c.want)
		}
	}
}
