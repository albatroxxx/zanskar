// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// sessionID finds the id behind a cookie.
func (e *env) sessionID(t *testing.T, cookie *http.Cookie) string {
	t.Helper()
	s, err := e.sessions.Lookup(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	return s.ID
}

// TestEnrolmentForProviderAccountsNeedsARecentSignIn: an account an identity
// provider signs in has no password to give again, so from a full session it
// may add an authenticator only within minutes of signing in; later, a stolen
// cookie alone must not enrol a device and take the step-up proof with it
// (review finding SEC-3).
func TestEnrolmentForProviderAccountsNeedsARecentSignIn(t *testing.T) {
	e := newEnv(t)
	pia := e.bareUser(t, "pia", user.RoleAdmin) // no local password: a provider's account
	s := e.sessionFor(t, pia, true)
	enrol := func() resp { return e.do("POST", "/api/v1/auth/mfa/totp/enroll", nil, s.cookie, csrfOf(s)) }
	if x := enrol(); x.code != http.StatusOK || x.body["otpauth_url"] == nil {
		t.Fatalf("fresh sign-in: %d %v", x.code, x.body)
	}
	// Enrolment started but not confirmed; a second start is allowed. Age
	// the session past the window.
	id := e.sessionID(t, s.cookie)
	old := store.TimeArg(time.Now().Add(-recentSignIn - time.Minute))
	if _, err := e.sessions.db.ExecContext(context.Background(), e.sessions.db.Rebind(`UPDATE auth_sessions SET created_at = ? WHERE id = ?`), old, id); err != nil {
		t.Fatal(err)
	}
	if x := enrol(); x.code != http.StatusUnauthorized || x.body["code"] != "reauth_required" {
		t.Fatalf("old session: %d %v, want 401 reauth_required", x.code, x.body)
	}
	if ev, d := e.lastEvent(t, audit.UserMFAEnroll); ev.Outcome != audit.Failure || d["reason"] != "reauth_required" {
		t.Fatalf("refusal audit: %+v %v", ev, d)
	}
	// The step a sign-in owes is not touched by the window.
	partial := e.sessionFor(t, pia, false)
	if x := e.do("POST", "/api/v1/auth/mfa/totp/enroll", nil, partial.cookie, csrfOf(partial)); x.code != http.StatusOK {
		t.Fatalf("enrolment while signing in: %d %v", x.code, x.body)
	}
}

// TestEnrolmentFromAFullSessionRevokesOtherSessions: an authenticator added
// to a full session shuts the account's other sessions, as a password change
// does, so whoever got in first on another cookie does not keep a seat.
func TestEnrolmentFromAFullSessionRevokesOtherSessions(t *testing.T) {
	e := newEnv(t)
	const pw = "quin keeps a long passphrase"
	quin := e.createUser(t, "quin", pw, user.RoleUser)
	mine := e.sessionFor(t, quin, true)
	other := e.sessionFor(t, quin, true)
	x := e.do("POST", "/api/v1/auth/mfa/totp/enroll", map[string]string{"current_password": pw}, mine.cookie, csrfOf(mine))
	if x.code != http.StatusOK {
		t.Fatalf("enrol: %d %v", x.code, x.body)
	}
	code, err := totp.GenerateCode(x.body["secret"].(string), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if c := e.do("POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": code}, mine.cookie, csrfOf(mine)); c.code != http.StatusOK {
		t.Fatalf("confirm: %d %v", c.code, c.body)
	}
	if _, err := e.sessions.Lookup(context.Background(), other.cookie.Value); !errors.Is(err, ErrNoSession) {
		t.Fatalf("the other session should be gone: %v", err)
	}
	if _, err := e.sessions.Lookup(context.Background(), mine.cookie.Value); err != nil {
		t.Fatalf("the enrolling session should stay: %v", err)
	}
	if _, d := e.lastEvent(t, audit.UserMFAConfirm); d["other_sessions_revoked"] != float64(1) {
		t.Fatalf("confirm audit should count the revoked sessions: %v", d)
	}
}

// TestSignInReplacesTheSessionItCameWith: a browser that signs in again holds
// one cookie; the session it held before ends, audited as a sign-out with the
// reason, so the old token is not left valid for whoever else holds it (S1 L5).
func TestSignInReplacesTheSessionItCameWith(t *testing.T) {
	e := newEnv(t)
	unlimited(e)
	const pw = "rosa keeps a long passphrase"
	e.createUser(t, "rosa", pw, user.RoleUser)
	first := login(e, "rosa", pw)
	if first.code != http.StatusOK || first.cookie == nil {
		t.Fatalf("first sign-in: %d %v", first.code, first.body)
	}
	firstID := e.sessionID(t, first.cookie)
	second := e.do("POST", "/api/v1/auth/login", map[string]string{"username": "rosa", "password": pw}, first.cookie, csrfOf(first))
	if second.code != http.StatusOK || second.cookie == nil || second.cookie.Value == first.cookie.Value {
		t.Fatalf("second sign-in: %d %v", second.code, second.body)
	}
	if _, err := e.sessions.Lookup(context.Background(), first.cookie.Value); !errors.Is(err, ErrNoSession) {
		t.Fatalf("the first session should be gone: %v", err)
	}
	if ev, d := e.lastEvent(t, audit.UserLogout); d["reason"] != "replaced" || d["session_id"] != firstID || ev.Outcome != audit.Success {
		t.Fatalf("replacement audit: %+v %v", ev, d)
	}
	// A sign-in with no cookie, or a stale one, revokes nothing and audits
	// no sign-out.
	before, _, _ := e.audit.List(context.Background(), audit.Filter{Action: audit.UserLogout})
	if r := e.do("POST", "/api/v1/auth/login", map[string]string{"username": "rosa", "password": pw}, first.cookie, nil); r.code != http.StatusOK {
		t.Fatalf("sign-in with a stale cookie: %d %v", r.code, r.body)
	}
	if after, _, _ := e.audit.List(context.Background(), audit.Filter{Action: audit.UserLogout}); len(after) != len(before) {
		t.Fatalf("a stale cookie must not produce a sign-out event")
	}
}

// TestSecureCookiesCarryTheHostPrefix: where cookies are Secure the session
// cookie is __Host- prefixed, so a browser takes it only from this host over
// HTTPS and a sibling subdomain cannot plant one; the middleware reads that
// name. On plain HTTP the bare name stays, since the prefix is not allowed
// there (S1 L6).
func TestSecureCookiesCarryTheHostPrefix(t *testing.T) {
	e := newEnv(t)
	plain := e.sessions
	if plain.CookieName() != CookieName {
		t.Fatalf("plain name %q", plain.CookieName())
	}
	secure := NewSessions(plain.db, plain.csrfKey, true)
	if secure.CookieName() != "__Host-"+CookieName {
		t.Fatalf("secure name %q", secure.CookieName())
	}
	rr := httptest.NewRecorder()
	secure.SetCookie(rr, "tok")
	c := rr.Result().Cookies()[0]
	if c.Name != "__Host-"+CookieName || !c.Secure || c.Path != "/" || !c.HttpOnly {
		t.Fatalf("secure cookie %+v", c)
	}
	rr = httptest.NewRecorder()
	secure.ClearCookie(rr)
	if c := rr.Result().Cookies()[0]; c.Name != "__Host-"+CookieName || c.MaxAge >= 0 {
		t.Fatalf("clear cookie %+v", c)
	}

	u := e.bareUser(t, "tess", user.RoleUser)
	tok, _, err := secure.Create(context.Background(), u.ID, "203.0.113.5", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	mw := &Middleware{Sessions: secure, Users: e.users, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	var seen *Principal
	h := mw.Authenticate(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen, _ = FromContext(r.Context()) }))
	for _, name := range []string{"__Host-" + CookieName, CookieName} {
		seen = nil
		req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
		req.AddCookie(&http.Cookie{Name: name, Value: tok})
		h.ServeHTTP(httptest.NewRecorder(), req)
		if want := name == "__Host-"+CookieName; (seen != nil) != want {
			t.Fatalf("cookie %q recognised=%v, want %v", name, seen != nil, want)
		}
	}
}

// TestSameOriginChecksTheScheme: a plain-HTTP origin is never this origin
// on a deployment that serves HTTPS, whatever its host (S1 L6).
func TestSameOriginChecksTheScheme(t *testing.T) {
	for _, tc := range []struct {
		origin string
		secure bool
		want   bool
	}{
		{"https://gw.example", true, true},
		{"http://gw.example", true, false},
		{"HTTP://gw.example", true, false},
		{"http://gw.example", false, true},
		{"https://gw.example", false, true},
		{"https://evil.example", true, false},
		{"", true, true},
	} {
		r := httptest.NewRequest("POST", "https://gw.example/api/v1/x", nil)
		r.Host = "gw.example"
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		if got := sameOrigin(r, tc.secure); got != tc.want {
			t.Errorf("origin %q secure=%v: %v, want %v", tc.origin, tc.secure, got, tc.want)
		}
	}
}
