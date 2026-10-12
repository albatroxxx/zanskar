// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
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
	db := storetest.Open(t)
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
		httpx.WriteJSON(w, 200, map[string]string{"ok": "admin"})
	})))
	mux.Handle("POST /api/v1/mutate", RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, 200, map[string]string{"ok": "mutated"})
	})))
	mux.Handle("GET /api/v1/connect-only", RequireConnect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, 200, map[string]string{"ok": "connect"})
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

// bareUser creates an account with no password. A password costs a full
// Argon2id hash to set and another to sign in with, which the race
// detector makes slow; tests not about the password use bareUser and
// sessionFor instead.
func (e *env) bareUser(t *testing.T, name string, roles ...user.Role) *user.User {
	t.Helper()
	u := &user.User{Username: name, DisplayName: name, Roles: roles}
	if err := e.users.Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

// sessionFor starts a session for u as a sign-in would have, full or still
// owing a second factor, and returns it the way login does.
func (e *env) sessionFor(t *testing.T, u *user.User, mfaVerified bool) resp {
	t.Helper()
	tok, sess, err := e.sessions.Create(context.Background(), u.ID, "203.0.113.5", "test", mfaVerified)
	if err != nil {
		t.Fatal(err)
	}
	return resp{code: http.StatusOK, body: map[string]any{"csrf_token": e.sessions.CSRFToken(sess.ID)}, cookie: &http.Cookie{Name: CookieName, Value: tok}}
}

type resp struct {
	code   int
	body   map[string]any
	cookie *http.Cookie
}

func (e *env) do(method, path string, body any, cookie *http.Cookie, headers map[string]string) resp {
	return e.doFrom("203.0.113.5:4444", method, path, body, cookie, headers)
}

// doFrom is do from another client address (host:port).
func (e *env) doFrom(addr, method, path string, body any, cookie *http.Cookie, headers map[string]string) resp {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = addr
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

	// carol's sign-in is full (a second factor is not required here), so
	// enrolling takes the password again (L14).
	enr := e.do("POST", "/api/v1/auth/mfa/totp/enroll", map[string]string{"current_password": "carol has a long passphrase"}, r.cookie, hdr)
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
	if me := e.do("GET", "/api/v1/auth/me", nil, r.cookie, nil); me.code != 200 || me.body["pending"] != "verify" || me.body["csrf_token"] == nil || me.body["user"] != nil {
		t.Fatalf("partial session /auth/me should resume verify without a profile: %d %v", me.code, me.body)
	}
	if v := e.do("POST", "/api/v1/auth/mfa/totp/verify", map[string]string{"code": "123456"}, r.cookie, hdr); v.code != 401 {
		t.Fatalf("wrong code: %d", v.code)
	}
	// The code that confirmed enrolment has been used; it is refused even
	// though it is still inside its window. The next one works.
	if v := e.do("POST", "/api/v1/auth/mfa/totp/verify", map[string]string{"code": code}, r.cookie, hdr); v.code != 401 {
		t.Fatalf("a code used once already: %d, want 401", v.code)
	}
	code, _ = totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	v := e.do("POST", "/api/v1/auth/mfa/totp/verify", map[string]string{"code": code}, r.cookie, hdr)
	if v.code != 200 || v.body["status"] != "ok" {
		t.Fatalf("verify: %d %v", v.code, v.body)
	}
	// Completing the sign-in issued a new token (L13).
	if me := e.do("GET", "/api/v1/auth/me", nil, v.cookie, nil); me.code != 200 {
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
	if v := e.do("POST", "/api/v1/auth/mfa/totp/verify", map[string]string{"code": "000000"}, r.cookie, hdr); v.code != 401 || v.body["code"] != "invalid_code" {
		t.Fatalf("first wrong code: %d %v", v.code, v.body)
	}
	// The attempt that ends the sign-in says so (#205).
	if v := e.do("POST", "/api/v1/auth/mfa/totp/verify", map[string]string{"code": "000000"}, r.cookie, hdr); v.code != 401 || v.body["code"] != "sign_in_ended" {
		t.Fatalf("last wrong code: %d %v", v.code, v.body)
	}
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
	required := true
	e.handler.RequireMFA = func() bool { return required }
	e.createUser(t, "fay", "fay has a long passphrase", user.RoleUser)
	r := e.do("POST", "/api/v1/auth/login", map[string]string{"username": "fay", "password": "fay has a long passphrase"}, nil, nil)
	if r.body["status"] != "mfa_enrollment_required" {
		t.Fatalf("expected enrollment required, got %v", r.body)
	}
	hdr := map[string]string{"X-CSRF-Token": r.body["csrf_token"].(string)}
	if me := e.do("GET", "/api/v1/auth/me", nil, r.cookie, nil); me.code != 200 || me.body["pending"] != "enroll" || me.body["csrf_token"] == nil || me.body["user"] != nil {
		t.Fatalf("partial session /auth/me should resume enroll without a profile: %d %v", me.code, me.body)
	}
	enr := e.do("POST", "/api/v1/auth/mfa/totp/enroll", nil, r.cookie, hdr)
	if enr.code != 200 {
		t.Fatalf("enroll on partial session: %d %v", enr.code, enr.body)
	}
	code, _ := totp.GenerateCode(enr.body["secret"].(string), time.Now())
	c := e.do("POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": code}, r.cookie, hdr)
	if c.code != 200 || c.body["status"] != "ok" {
		t.Fatalf("confirm: %d %v", c.code, c.body)
	}
	// Completing the sign-in issued a new token (L13).
	if me := e.do("GET", "/api/v1/auth/me", nil, c.cookie, nil); me.code != 200 {
		t.Fatalf("session should be full after confirm, got %d", me.code)
	}
	// The requirement is a runtime setting: flipping it applies to the next
	// sign-in without a restart.
	required = false
	e.createUser(t, "gus", "gus has a long passphrase", user.RoleUser)
	if r := e.do("POST", "/api/v1/auth/login", map[string]string{"username": "gus", "password": "gus has a long passphrase"}, nil, nil); r.body["status"] != "ok" {
		t.Fatalf("with the requirement off, a password sign-in completes: %v", r.body)
	}
}

// TestRequireConnect covers the review-only rule of ADR 0006: an account that
// holds only auditor is refused where users reach targets, while user, admin
// and an admin who also audits all pass. Sessions are created directly so the
// mandatory-MFA login steps for admin and auditor do not get in the way.
func TestRequireConnect(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cases := []struct {
		name  string
		roles []user.Role
		want  int
	}{
		{"plainuser", []user.Role{user.RoleUser}, 200},
		{"pureadmin", []user.Role{user.RoleAdmin}, 200},
		{"reviewer", []user.Role{user.RoleAuditor}, 403},
		{"adminreviewer", []user.Role{user.RoleAdmin, user.RoleAuditor}, 200},
	}
	for _, c := range cases {
		u := e.createUser(t, c.name, "a strong enough passphrase", c.roles...)
		tok, _, err := e.sessions.Create(ctx, u.ID, "203.0.113.5", "test", true)
		if err != nil {
			t.Fatal(err)
		}
		r := e.do("GET", "/api/v1/connect-only", nil, &http.Cookie{Name: CookieName, Value: tok}, nil)
		if r.code != c.want {
			t.Errorf("%s: got %d %v, want %d", c.name, r.code, r.body, c.want)
		}
		if c.want == 403 && r.body["code"] != "review_only" {
			t.Errorf("%s: want code review_only, got %v", c.name, r.body)
		}
	}
	// Review-only is about roles, not authentication: anonymous stays 401.
	if r := e.do("GET", "/api/v1/connect-only", nil, nil, nil); r.code != 401 {
		t.Errorf("anonymous: got %d, want 401", r.code)
	}
}

// TestPasswordChangeRequiredFirst: a user whose password an administrator
// set is held at a partial session until they replace it: the second
// factor steps are refused meanwhile, the wrong current password is
// refused, and after the change sign-in continues to authenticator
// enrollment; the next sign-in with the new password owes no change.
func TestPasswordChangeRequiredFirst(t *testing.T) {
	e := newEnv(t)
	e.handler.RequireMFA = func() bool { return true }
	u := e.createUser(t, "hana", "hana temporary passphrase", user.RoleUser)
	if err := e.users.SetPasswordHash(context.Background(), u.ID, u.PasswordHash, true); err != nil {
		t.Fatal(err)
	}
	r := e.do("POST", "/api/v1/auth/login", map[string]string{"username": "hana", "password": "hana temporary passphrase"}, nil, nil)
	if r.code != 200 || r.body["status"] != "password_change_required" {
		t.Fatalf("login: %d %v", r.code, r.body)
	}
	csrf := map[string]string{"X-CSRF-Token": r.body["csrf_token"].(string)}
	if me := e.do("GET", "/api/v1/auth/me", nil, r.cookie, nil); me.body["pending"] != "password" {
		t.Fatalf("me must say the change is owed: %v", me.body)
	}
	if x := e.do("POST", "/api/v1/auth/mfa/totp/enroll", nil, r.cookie, csrf); x.code != 409 || x.body["code"] != "password_change_required" {
		t.Fatalf("enrollment before the change: %d %v", x.code, x.body)
	}
	if me := e.do("GET", "/api/v1/auth/me", nil, r.cookie, nil); me.body["user"] != nil || me.body["session"] != nil {
		t.Fatalf("a partial session gets no profile: %v", me.body)
	}
	if x := e.do("POST", "/api/v1/auth/password", map[string]string{"current_password": "wrong", "new_password": "hana chosen passphrase"}, r.cookie, csrf); x.code != 401 {
		t.Fatalf("wrong current password: %d %v", x.code, x.body)
	}
	if x := e.do("POST", "/api/v1/auth/password", map[string]string{"current_password": "hana temporary passphrase", "new_password": "short"}, r.cookie, csrf); x.code != 400 {
		t.Fatalf("policy still applies: %d %v", x.code, x.body)
	}
	x := e.do("POST", "/api/v1/auth/password", map[string]string{"current_password": "hana temporary passphrase", "new_password": "hana chosen passphrase"}, r.cookie, csrf)
	if x.code != 200 || x.body["status"] != "mfa_enrollment_required" {
		t.Fatalf("change: %d %v", x.code, x.body)
	}
	if me := e.do("GET", "/api/v1/auth/me", nil, r.cookie, nil); me.body["pending"] != "enroll" {
		t.Fatalf("after the change enrollment is owed: %v", me.body)
	}
	if x := e.do("POST", "/api/v1/auth/mfa/totp/enroll", nil, r.cookie, csrf); x.code != 200 {
		t.Fatalf("enrollment after the change: %d %v", x.code, x.body)
	}
	if again := e.do("POST", "/api/v1/auth/login", map[string]string{"username": "hana", "password": "hana chosen passphrase"}, nil, nil); again.body["status"] != "mfa_enrollment_required" {
		t.Fatalf("next sign-in owes no change: %v", again.body)
	}
	if old := e.do("POST", "/api/v1/auth/login", map[string]string{"username": "hana", "password": "hana temporary passphrase"}, nil, nil); old.code != 401 {
		t.Fatalf("the temporary password is gone: %d", old.code)
	}

	// Without an MFA requirement the change completes the session.
	e.handler.RequireMFA = func() bool { return false }
	v := e.createUser(t, "vic", "vic temporary passphrase", user.RoleUser)
	_ = e.users.SetPasswordHash(context.Background(), v.ID, v.PasswordHash, true)
	r = e.do("POST", "/api/v1/auth/login", map[string]string{"username": "vic", "password": "vic temporary passphrase"}, nil, nil)
	csrf = map[string]string{"X-CSRF-Token": r.body["csrf_token"].(string)}
	x = e.do("POST", "/api/v1/auth/password", map[string]string{"current_password": "vic temporary passphrase", "new_password": "vic chosen passphrase"}, r.cookie, csrf)
	if x.code != 200 || x.body["status"] != "ok" {
		t.Fatalf("change without MFA: %d %v", x.code, x.body)
	}
	// Completing the sign-in issued a new token (L13).
	if me := e.do("GET", "/api/v1/auth/me", nil, x.cookie, nil); me.body["pending"] != nil || me.body["user"] == nil {
		t.Fatalf("session is full after the change: %v", me.body)
	}
}

// TestPasswordChangeAfterSecondFactor: an account with an authenticator
// proves it before the change an admin's reset made due; a password-only
// session cannot change the password; after the second factor the change
// is owed and every full-auth route refuses until it is done.
func TestPasswordChangeAfterSecondFactor(t *testing.T) {
	e := newEnv(t)
	e.handler.RequireMFA = func() bool { return true }
	u := e.createUser(t, "ines", "ines first passphrase", user.RoleUser)
	r := e.do("POST", "/api/v1/auth/login", map[string]string{"username": "ines", "password": "ines first passphrase"}, nil, nil)
	hdr := map[string]string{"X-CSRF-Token": r.body["csrf_token"].(string)}
	enr := e.do("POST", "/api/v1/auth/mfa/totp/enroll", nil, r.cookie, hdr)
	code, _ := totp.GenerateCode(enr.body["secret"].(string), time.Now())
	if c := e.do("POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": code}, r.cookie, hdr); c.code != 200 {
		t.Fatalf("confirm: %d %v", c.code, c.body)
	}
	// An administrator resets the password.
	if err := e.users.SetPasswordHash(context.Background(), u.ID, u.PasswordHash, true); err != nil {
		t.Fatal(err)
	}
	r = e.do("POST", "/api/v1/auth/login", map[string]string{"username": "ines", "password": "ines first passphrase"}, nil, nil)
	if r.body["status"] != "mfa_required" {
		t.Fatalf("an enrolled account verifies first: %v", r.body)
	}
	hdr = map[string]string{"X-CSRF-Token": r.body["csrf_token"].(string)}
	if x := e.do("POST", "/api/v1/auth/password", map[string]string{"current_password": "ines first passphrase", "new_password": "ines second passphrase"}, r.cookie, hdr); x.code != 401 || x.body["code"] != "mfa_required" {
		t.Fatalf("a password-only session must not change the password: %d %v", x.code, x.body)
	}
	if me := e.do("GET", "/api/v1/auth/me", nil, r.cookie, nil); me.body["pending"] != "verify" {
		t.Fatalf("verify is owed first: %v", me.body)
	}
	// The confirm code is spent; the next step's code is not.
	code, _ = totp.GenerateCode(enr.body["secret"].(string), time.Now().Add(30*time.Second))
	v := e.do("POST", "/api/v1/auth/mfa/totp/verify", map[string]string{"code": code}, r.cookie, hdr)
	if v.code != 200 {
		t.Fatalf("verify: %d %v", v.code, v.body)
	}
	// The second factor issued a new token (L13); the session goes on.
	r.cookie = v.cookie
	if me := e.do("GET", "/api/v1/auth/me", nil, r.cookie, nil); me.body["pending"] != "password" || me.body["user"] != nil {
		t.Fatalf("after the second factor the change is owed: %v", me.body)
	}
	x := e.do("POST", "/api/v1/auth/password", map[string]string{"current_password": "ines first passphrase", "new_password": "ines second passphrase"}, r.cookie, hdr)
	if x.code != 200 || x.body["status"] != "ok" {
		t.Fatalf("change after the second factor: %d %v", x.code, x.body)
	}
	// The change was the sign-in's last step, so it issued a new token too.
	if me := e.do("GET", "/api/v1/auth/me", nil, x.cookie, nil); me.body["pending"] != nil || me.body["user"] == nil {
		t.Fatalf("full after the change: %v", me.body)
	}
}

// TestPasswordChangeEndsOtherSessions: replacing your own password ends every
// other session of the account, which may be a thief's, and keeps the one
// that made the change (M9). That includes the change an administrator's
// reset made due: a second sign-in with the password they handed out must
// not go on to enrol an authenticator once the owner has replaced it.
func TestPasswordChangeEndsOtherSessions(t *testing.T) {
	e := newEnv(t)
	const old, next = "kira has a long passphrase", "kira chose a new passphrase"
	kira := e.createUser(t, "kira", old, user.RoleUser)
	first, second := e.sessionFor(t, kira, true), e.sessionFor(t, kira, true)
	change := func(r resp, current, next string) resp {
		return e.do("POST", "/api/v1/auth/password", map[string]string{"current_password": current, "new_password": next}, r.cookie, csrfOf(r))
	}
	if x := change(first, old, next); x.code != 200 || x.body["status"] != "ok" {
		t.Fatalf("change: %d %v", x.code, x.body)
	}
	if me := e.do("GET", "/api/v1/auth/me", nil, second.cookie, nil); me.code != 401 {
		t.Fatalf("the other session after the password change: %d %v, want 401", me.code, me.body)
	}
	if me := e.do("GET", "/api/v1/auth/me", nil, first.cookie, nil); me.code != 200 || me.body["user"] == nil {
		t.Fatalf("the session that changed the password: %d %v, want it kept", me.code, me.body)
	}
	if _, d := e.lastEvent(t, "user.password.change"); d["other_sessions_revoked"] != float64(1) {
		t.Fatalf("audit details %v, want other_sessions_revoked 1", d)
	}

	const issued, chosen = "lena was handed this one", "lena chose her own phrase"
	lena := e.createUser(t, "lena", issued, user.RoleUser)
	if err := e.users.SetPasswordHash(context.Background(), lena.ID, lena.PasswordHash, true); err != nil {
		t.Fatal(err)
	}
	owner, other := e.sessionFor(t, lena, false), e.sessionFor(t, lena, false)
	if x := change(owner, issued, chosen); x.code != 200 {
		t.Fatalf("the change a reset made due: %d %v", x.code, x.body)
	}
	if x := e.do("POST", "/api/v1/auth/mfa/totp/enroll", nil, other.cookie, csrfOf(other)); x.code != 401 {
		t.Fatalf("enrolment from the other sign-in with the handed-out password: %d %v, want 401", x.code, x.body)
	}
}

// TestWrongCurrentPasswordCounts: a wrong current_password on a password
// change was neither limited nor counted (L17), so whoever held a stolen
// session could guess the password there without end. It counts against
// the account like a wrong sign-in password: the fifth locks the account,
// and while it is locked the change is refused before any hash is spent,
// even with the right password.
func TestWrongCurrentPasswordCounts(t *testing.T) {
	e := newEnv(t)
	const pw = "mona keeps a long passphrase"
	mona := e.createUser(t, "mona", pw, user.RoleUser)
	s := e.sessionFor(t, mona, true)
	change := func(current string) resp {
		return e.do("POST", "/api/v1/auth/password", map[string]string{"current_password": current, "new_password": "mona picked another phrase"}, s.cookie, csrfOf(s))
	}
	for i := 1; i <= 5; i++ {
		if x := change(fmt.Sprintf("guess number %d of five", i)); x.code != http.StatusUnauthorized || x.body["code"] != "invalid_credentials" {
			t.Fatalf("guess %d: %d %v", i, x.code, x.body)
		}
		u, err := e.users.GetByID(context.Background(), mona.ID)
		if err != nil {
			t.Fatal(err)
		}
		// The fifth locks the account (checked below) and restarts the count.
		if i < 5 && u.FailedLogins != i {
			t.Fatalf("after guess %d: %d failures counted", i, u.FailedLogins)
		}
	}
	if u, _ := e.users.GetByID(context.Background(), mona.ID); u.LockedUntil == nil || !u.LockedUntil.After(time.Now()) {
		t.Fatalf("five wrong current passwords must lock the account: %+v", u.LockedUntil)
	}
	if x := change(pw); x.code != http.StatusTooManyRequests || x.body["code"] != "too_many_attempts" {
		t.Fatalf("the right password while locked: %d %v, want 429 too_many_attempts", x.code, x.body)
	}
	if u, _ := e.users.GetByID(context.Background(), mona.ID); !user.VerifyPassword(u.PasswordHash, pw) {
		t.Fatal("the password changed while the account was locked")
	}
}

// TestEnrolmentFromAFullSessionNeedsThePassword: an account with no
// authenticator could have one enrolled from any full session, without the
// password (L14), so a stolen cookie could enrol the thief's device and lock
// the owner out of every later sign-in. From a full session it now takes the
// current password, which counts like any other; enrolling as a step of
// signing in (a partial session) does not.
func TestEnrolmentFromAFullSessionNeedsThePassword(t *testing.T) {
	e := newEnv(t)
	const pw = "nina keeps a long passphrase"
	nina := e.createUser(t, "nina", pw, user.RoleUser)
	s := e.sessionFor(t, nina, true)
	enrol := func(body any) resp { return e.do("POST", "/api/v1/auth/mfa/totp/enroll", body, s.cookie, csrfOf(s)) }
	if x := enrol(nil); x.code != http.StatusUnauthorized || x.body["code"] != "password_required" {
		t.Fatalf("no password: %d %v, want 401 password_required", x.code, x.body)
	}
	if x := enrol(map[string]string{"current_password": "not nina's phrase at all"}); x.code != http.StatusUnauthorized || x.body["code"] != "invalid_credentials" {
		t.Fatalf("wrong password: %d %v, want 401 invalid_credentials", x.code, x.body)
	}
	if u, _ := e.users.GetByID(context.Background(), nina.ID); u.FailedLogins != 1 {
		t.Fatalf("a wrong password at enrolment must count: %d", u.FailedLogins)
	}
	if x := enrol(map[string]string{"current_password": pw}); x.code != http.StatusOK || x.body["otpauth_url"] == nil {
		t.Fatalf("right password: %d %v", x.code, x.body)
	}

	// Enrolling as the step a sign-in owes needs nothing more: the password
	// was given a moment ago.
	omar := e.createUser(t, "omar", "omar keeps a long passphrase", user.RoleUser)
	partial := e.sessionFor(t, omar, false)
	if x := e.do("POST", "/api/v1/auth/mfa/totp/enroll", nil, partial.cookie, csrfOf(partial)); x.code != http.StatusOK {
		t.Fatalf("enrolment while signing in: %d %v", x.code, x.body)
	}
}

// TestSignInCompletionRotatesTheToken: a sign-in that becomes full kept the
// cookie it had while partial (L13), so a cookie planted in the victim's
// browser before sign-in (from a sibling subdomain, say) became fully
// verified when the victim typed their code. Each step that completes a
// sign-in now issues a new token for the same session: the code, the
// enrolment a sign-in owes, and the password change that is its last step.
// The old token stops working; the session, its id and CSRF token go on.
func TestSignInCompletionRotatesTheToken(t *testing.T) {
	e := newEnv(t)
	unlimited(e)
	completes := func(t *testing.T, before, after resp) {
		t.Helper()
		if after.code != http.StatusOK || after.cookie == nil || after.cookie.Value == "" || after.cookie.Value == before.cookie.Value {
			t.Fatalf("the completing step must set a new cookie: %d %v", after.code, after.cookie)
		}
		if me := e.do("GET", "/api/v1/auth/me", nil, before.cookie, nil); me.code != http.StatusUnauthorized {
			t.Fatalf("the token from before the sign-in completed: %d, want 401", me.code)
		}
		me := e.do("GET", "/api/v1/auth/me", nil, after.cookie, nil)
		if me.code != http.StatusOK || me.body["user"] == nil || me.body["csrf_token"] != before.body["csrf_token"] {
			t.Fatalf("the new token: %d %v, want the same session", me.code, me.body)
		}
	}

	t.Run("code", func(t *testing.T) {
		u := e.createUser(t, "pia", "pia keeps a long passphrase", user.RoleUser)
		enr, err := e.totp.Enroll(context.Background(), u.ID, u.Username)
		if err != nil {
			t.Fatal(err)
		}
		code, _ := totp.GenerateCode(enr.Secret, time.Now())
		if _, err := e.totp.Confirm(context.Background(), u.ID, code); err != nil {
			t.Fatal(err)
		}
		r := login(e, "pia", "pia keeps a long passphrase")
		code, _ = totp.GenerateCode(enr.Secret, time.Now().Add(30*time.Second))
		completes(t, r, e.do("POST", "/api/v1/auth/mfa/totp/verify", map[string]string{"code": code}, r.cookie, csrfOf(r)))
	})

	t.Run("enrolment", func(t *testing.T) {
		e.handler.RequireMFA = func() bool { return true }
		defer func() { e.handler.RequireMFA = nil }()
		e.createUser(t, "quin", "quin keeps a long passphrase", user.RoleUser)
		r := login(e, "quin", "quin keeps a long passphrase")
		enr := e.do("POST", "/api/v1/auth/mfa/totp/enroll", nil, r.cookie, csrfOf(r))
		code, _ := totp.GenerateCode(enr.body["secret"].(string), time.Now())
		completes(t, r, e.do("POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": code}, r.cookie, csrfOf(r)))
	})

	t.Run("password change", func(t *testing.T) {
		u := e.createUser(t, "rosa", "rosa was handed this phrase", user.RoleUser)
		if err := e.users.SetPasswordHash(context.Background(), u.ID, u.PasswordHash, true); err != nil {
			t.Fatal(err)
		}
		r := login(e, "rosa", "rosa was handed this phrase")
		completes(t, r, e.do("POST", "/api/v1/auth/password", map[string]string{"current_password": "rosa was handed this phrase", "new_password": "rosa chose her own phrase"}, r.cookie, csrfOf(r)))
	})
}
