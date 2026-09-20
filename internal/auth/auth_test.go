// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

type env struct {
	srv      http.Handler
	users    *user.Repo
	sessions *Sessions
	totp     *TOTP
	audit    *audit.Log
	handler  *Handler
}

func newEnv(t *testing.T) *env {
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
	kek, _ := crypto.NewLocalKEK(bytes.Repeat([]byte{9}, 32))
	ring, err := keyring.Open(ctx, db, kek)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := &env{
		users:    user.NewRepo(db),
		sessions: NewSessions(db, bytes.Repeat([]byte{1}, 32), false),
		totp:     NewTOTP(db, ring, "Zanskar Test"),
		audit:    audit.NewLog(db),
	}
	e.handler = NewHandler(e.users, e.sessions, e.totp, e.audit, log)
	mux := http.NewServeMux()
	e.handler.Register(mux)
	mux.Handle("GET /api/v1/admin-only", RequireRole(user.RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		WriteJSON(w, 200, map[string]string{"ok": "admin"})
	})))
	mux.Handle("POST /api/v1/mutate", RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		WriteJSON(w, 200, map[string]string{"ok": "mutated"})
	})))
	mw := &Middleware{Sessions: e.sessions, Users: e.users, Log: log}
	e.srv = mw.Authenticate(mw.CSRF(mux))
	return e
}

func (e *env) createUser(t *testing.T, name, pw string, roles ...user.Role) *user.User {
	t.Helper()
	h, err := user.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	u := &user.User{Username: name, DisplayName: name, Roles: roles, PasswordHash: h}
	if err := e.users.Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

type resp struct {
	code   int
	body   map[string]any
	cookie *http.Cookie
}

func (e *env) do(method, path string, body any, cookie *http.Cookie, headers map[string]string) resp {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.5:4444"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	out := resp{code: rr.Code}
	_ = json.Unmarshal(rr.Body.Bytes(), &out.body)
	for _, c := range rr.Result().Cookies() {
		if c.Name == CookieName {
			out.cookie = c
		}
	}
	return out
}

func TestLoginLogoutAndRoles(t *testing.T) {
	e := newEnv(t)
	e.createUser(t, "alice", "correct horse battery staple", user.RoleAdmin, user.RoleUser)
	e.createUser(t, "bob", "another strong passphrase", user.RoleUser)

	// Wrong password, unknown user: same response.
	r1 := e.do("POST", "/api/v1/auth/login", map[string]string{"username": "alice", "password": "wrong password here"}, nil, nil)
	r2 := e.do("POST", "/api/v1/auth/login", map[string]string{"username": "nobody", "password": "wrong password here"}, nil, nil)
	if r1.code != 401 || r2.code != 401 || r1.body["code"] != r2.body["code"] {
		t.Fatalf("expected identical 401s, got %d/%v and %d/%v", r1.code, r1.body, r2.code, r2.body)
	}

	r := e.do("POST", "/api/v1/auth/login", map[string]string{"username": "Alice", "password": "correct horse battery staple"}, nil, nil)
	if r.code != 200 || r.body["status"] != "ok" || r.cookie == nil || r.cookie.Value == "" {
		t.Fatalf("login: %d %v cookie=%v", r.code, r.body, r.cookie)
	}
	if !r.cookie.HttpOnly || r.cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie flags wrong: %+v", r.cookie)
	}
	csrf := r.body["csrf_token"].(string)
	if len(csrf) != 64 {
		t.Fatalf("bad csrf token %q", csrf)
	}

	if me := e.do("GET", "/api/v1/auth/me", nil, r.cookie, nil); me.code != 200 || me.body["user"].(map[string]any)["username"] != "alice" {
		t.Fatalf("me: %d %v", me.code, me.body)
	}
	if adm := e.do("GET", "/api/v1/admin-only", nil, r.cookie, nil); adm.code != 200 {
		t.Fatalf("admin route: %d %v", adm.code, adm.body)
	}

	// CSRF: mutating call without header is refused; with header succeeds; cross-origin refused.
	if m := e.do("POST", "/api/v1/mutate", nil, r.cookie, nil); m.code != 403 || m.body["code"] != "csrf_invalid" {
		t.Fatalf("expected csrf rejection, got %d %v", m.code, m.body)
	}
	if m := e.do("POST", "/api/v1/mutate", nil, r.cookie, map[string]string{"X-CSRF-Token": csrf}); m.code != 200 {
		t.Fatalf("expected csrf pass, got %d %v", m.code, m.body)
	}
	if m := e.do("POST", "/api/v1/mutate", nil, r.cookie, map[string]string{"X-CSRF-Token": csrf, "Origin": "https://evil.example"}); m.code != 403 {
		t.Fatalf("expected cross-origin rejection, got %d", m.code)
	}

	// Bob is not an admin.
	rb := e.do("POST", "/api/v1/auth/login", map[string]string{"username": "bob", "password": "another strong passphrase"}, nil, nil)
	if adm := e.do("GET", "/api/v1/admin-only", nil, rb.cookie, nil); adm.code != 403 {
		t.Fatalf("expected 403 for bob, got %d", adm.code)
	}

	// Logout revokes the session.
	if lo := e.do("POST", "/api/v1/auth/logout", nil, r.cookie, map[string]string{"X-CSRF-Token": csrf}); lo.code != 200 {
		t.Fatalf("logout: %d %v", lo.code, lo.body)
	}
	if me := e.do("GET", "/api/v1/auth/me", nil, r.cookie, nil); me.code != 401 {
		t.Fatalf("expected 401 after logout, got %d", me.code)
	}

	// Audit trail exists for the failures and successes.
	events, _, err := e.audit.List(context.Background(), audit.Filter{Action: "user.login"})
	if err != nil || len(events) < 4 {
		t.Fatalf("expected login audit events, got %d (%v)", len(events), err)
	}
}

func TestLockoutAfterFailures(t *testing.T) {
	e := newEnv(t)
	u := e.createUser(t, "eve", "a perfectly fine passphrase", user.RoleUser)
	e.handler.MaxFailures = 3
	for i := 0; i < 3; i++ {
		e.do("POST", "/api/v1/auth/login", map[string]string{"username": "eve", "password": "not it, not it"}, nil, nil)
	}
	got, _ := e.users.GetByID(context.Background(), u.ID)
	if !got.IsLocked(time.Now()) {
		t.Fatal("expected account locked")
	}
	if r := e.do("POST", "/api/v1/auth/login", map[string]string{"username": "eve", "password": "a perfectly fine passphrase"}, nil, nil); r.code != 401 {
		t.Fatalf("locked account must not log in, got %d", r.code)
	}
}

func TestTOTPFlow(t *testing.T) {
	e := newEnv(t)
	e.createUser(t, "carol", "carol has a long passphrase", user.RoleUser)
	login := func() resp {
		return e.do("POST", "/api/v1/auth/login", map[string]string{"username": "carol", "password": "carol has a long passphrase"}, nil, nil)
	}
	r := login()
	csrf := r.body["csrf_token"].(string)
	hdr := map[string]string{"X-CSRF-Token": csrf}

	enr := e.do("POST", "/api/v1/auth/mfa/totp/enroll", nil, r.cookie, hdr)
	if enr.code != 200 || enr.body["secret"] == "" {
		t.Fatalf("enroll: %d %v", enr.code, enr.body)
	}
	secret := enr.body["secret"].(string)
	if c := e.do("POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": "000000"}, r.cookie, hdr); c.code != 401 {
		t.Fatalf("bad confirm code should 401, got %d", c.code)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	c := e.do("POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": code}, r.cookie, hdr)
	if c.code != 200 {
		t.Fatalf("confirm: %d %v", c.code, c.body)
	}
	codes := c.body["recovery_codes"].([]any)
	if len(codes) != 8 {
		t.Fatalf("expected 8 recovery codes, got %d", len(codes))
	}

	// Next login requires MFA; session is partial until verified.
	r = login()
	if r.body["status"] != "mfa_required" || r.body["csrf_token"] == nil {
		t.Fatalf("expected mfa_required with csrf, got %v", r.body)
	}
	hdr = map[string]string{"X-CSRF-Token": r.body["csrf_token"].(string)}
	if me := e.do("GET", "/api/v1/auth/me", nil, r.cookie, nil); me.code != 401 || me.body["code"] != "mfa_required" {
		t.Fatalf("partial session must not pass RequireAuth: %d %v", me.code, me.body)
	}
	if v := e.do("POST", "/api/v1/auth/mfa/totp/verify", map[string]string{"code": "123456"}, r.cookie, hdr); v.code != 401 {
		t.Fatalf("wrong code: %d", v.code)
	}
	code, _ = totp.GenerateCode(secret, time.Now())
	v := e.do("POST", "/api/v1/auth/mfa/totp/verify", map[string]string{"code": code}, r.cookie, hdr)
	if v.code != 200 || v.body["status"] != "ok" {
		t.Fatalf("verify: %d %v", v.code, v.body)
	}
	if me := e.do("GET", "/api/v1/auth/me", nil, r.cookie, nil); me.code != 200 {
		t.Fatalf("expected full session after verify, got %d", me.code)
	}

	// Recovery code works once.
	r = login()
	hdr = map[string]string{"X-CSRF-Token": r.body["csrf_token"].(string)}
	rc := codes[0].(string)
	if v := e.do("POST", "/api/v1/auth/mfa/totp/verify", map[string]string{"code": rc}, r.cookie, hdr); v.code != 200 {
		t.Fatalf("recovery code: %d %v", v.code, v.body)
	}
	r = login()
	hdr = map[string]string{"X-CSRF-Token": r.body["csrf_token"].(string)}
	if v := e.do("POST", "/api/v1/auth/mfa/totp/verify", map[string]string{"code": rc}, r.cookie, hdr); v.code != 401 {
		t.Fatalf("reused recovery code must fail, got %d", v.code)
	}

	// Too many wrong codes end the pending session.
	e.handler.MFAAttempts = 2
	r = login()
	hdr = map[string]string{"X-CSRF-Token": r.body["csrf_token"].(string)}
	e.do("POST", "/api/v1/auth/mfa/totp/verify", map[string]string{"code": "000000"}, r.cookie, hdr)
	e.do("POST", "/api/v1/auth/mfa/totp/verify", map[string]string{"code": "000000"}, r.cookie, hdr)
	if v := e.do("POST", "/api/v1/auth/mfa/totp/verify", map[string]string{"code": code}, r.cookie, hdr); v.code != 401 || v.body["code"] != "unauthenticated" {
		t.Fatalf("session should have been revoked, got %d %v", v.code, v.body)
	}
}

func TestSessionExpiry(t *testing.T) {
	e := newEnv(t)
	u := e.createUser(t, "dan", "dan has a long passphrase", user.RoleUser)
	ctx := context.Background()
	base := time.Now()
	e.sessions.now = func() time.Time { return base }
	token, _, err := e.sessions.Create(ctx, u.ID, "127.0.0.1", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.sessions.Lookup(ctx, token); err != nil {
		t.Fatal(err)
	}
	e.sessions.now = func() time.Time { return base.Add(61 * time.Minute) }
	if _, err := e.sessions.Lookup(ctx, token); !errors.Is(err, ErrNoSession) {
		t.Fatalf("expected idle expiry, got %v", err)
	}
	if _, err := e.sessions.Lookup(ctx, "bogus"); !errors.Is(err, ErrNoSession) {
		t.Fatal("bogus token must fail")
	}
	if !e.sessions.CheckCSRF("s1", e.sessions.CSRFToken("s1")) || e.sessions.CheckCSRF("s1", e.sessions.CSRFToken("s2")) {
		t.Fatal("csrf binding broken")
	}
}

func TestMFAEnrollmentRequired(t *testing.T) {
	e := newEnv(t)
	e.handler.RequireMFA = true
	e.createUser(t, "fay", "fay has a long passphrase", user.RoleUser)
	r := e.do("POST", "/api/v1/auth/login", map[string]string{"username": "fay", "password": "fay has a long passphrase"}, nil, nil)
	if r.body["status"] != "mfa_enrollment_required" {
		t.Fatalf("expected enrollment required, got %v", r.body)
	}
	hdr := map[string]string{"X-CSRF-Token": r.body["csrf_token"].(string)}
	if me := e.do("GET", "/api/v1/auth/me", nil, r.cookie, nil); me.code != 401 {
		t.Fatalf("partial session must be blocked, got %d", me.code)
	}
	enr := e.do("POST", "/api/v1/auth/mfa/totp/enroll", nil, r.cookie, hdr)
	if enr.code != 200 {
		t.Fatalf("enroll on partial session: %d %v", enr.code, enr.body)
	}
	code, _ := totp.GenerateCode(enr.body["secret"].(string), time.Now())
	if c := e.do("POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": code}, r.cookie, hdr); c.code != 200 || c.body["status"] != "ok" {
		t.Fatalf("confirm: %d %v", c.code, c.body)
	}
	if me := e.do("GET", "/api/v1/auth/me", nil, r.cookie, nil); me.code != 200 {
		t.Fatalf("session should be full after confirm, got %d", me.code)
	}
}
