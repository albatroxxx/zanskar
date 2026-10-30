// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestRealIPTrustBoundary pins the rule that decides which address the audit
// log records: a forwarded address counts only when the peer is a trusted
// proxy, and a client cannot talk its way past that by forging header entries.
func TestRealIPTrustBoundary(t *testing.T) {
	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	privateToo := append([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, loopback...)

	cases := []struct {
		name    string
		peer    string
		xff     []string
		trusted []netip.Prefix
		want    string
	}{
		{"no trusted proxies ignores the header", "127.0.0.1:5000", []string{"203.0.113.9"}, nil, "127.0.0.1"},
		{"untrusted peer cannot forge an address", "198.51.100.7:5000", []string{"203.0.113.9"}, loopback, "198.51.100.7"},
		{"trusted proxy supplies the client", "127.0.0.1:5000", []string{"203.0.113.9"}, loopback, "203.0.113.9"},
		{"forged entries left of the real one are ignored", "127.0.0.1:5000", []string{"1.2.3.4, 203.0.113.9"}, loopback, "203.0.113.9"},
		{"trusted hops are skipped right to left", "127.0.0.1:5000", []string{"203.0.113.9, 10.0.0.2"}, privateToo, "203.0.113.9"},
		{"header split across repeated fields", "127.0.0.1:5000", []string{"1.2.3.4", "203.0.113.9"}, loopback, "203.0.113.9"},
		{"all hops trusted falls back to the peer", "127.0.0.1:5000", []string{"10.0.0.2"}, privateToo, "127.0.0.1"},
		{"garbage entries do not break the walk", "127.0.0.1:5000", []string{"not-an-ip, 203.0.113.9"}, loopback, "203.0.113.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			h := RealIP(tc.trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = ClientIP(r)
			}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.peer
			for _, v := range tc.xff {
				req.Header.Add("X-Forwarded-For", v)
			}
			h.ServeHTTP(httptest.NewRecorder(), req)
			if got != tc.want {
				t.Fatalf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestClientIPWithoutMiddleware keeps the direct-connection path working.
func TestClientIPWithoutMiddleware(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.7:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := ClientIP(req); got != "198.51.100.7" {
		t.Fatalf("ClientIP = %q, want the peer address", got)
	}
}

// TestRequireAuthRefusesWhilePasswordChangeOwed: a verified session whose
// account still has to replace an administrator's password is refused by
// every full-auth route with a code the sign-in page understands.
func TestRequireAuthRefusesWhilePasswordChangeOwed(t *testing.T) {
	h := RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	p := &Principal{Session: &Session{MFAVerified: true}, User: &user.User{ID: "u1", MustResetOnLogin: true}}
	req := httptest.NewRequest("GET", "/api/v1/targets", nil).WithContext(context.WithValue(context.Background(), principalKey, p))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 401 || !strings.Contains(rr.Body.String(), "password_change_required") {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
	p.User.MustResetOnLogin = false
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 204 {
		t.Fatalf("after the change: %d", rr.Code)
	}
}

// TestTemporaryLockLeavesLiveSessions: wrong passwords from anywhere lock the
// account against new sign-ins for a while. They must not end a session that
// is already signed in, or anyone who knows a username could sign its owner
// out, again and again (M6). An administrator disabling the account still
// does.
func TestTemporaryLockLeavesLiveSessions(t *testing.T) {
	e := newEnv(t)
	unlimited(e)
	// Fewer than the default five: each wrong password costs a full hash.
	e.handler.MaxFailures = 2
	ctx := context.Background()
	u := e.createUser(t, "ruth", "ruth has a long passphrase", user.RoleUser)
	first := login(e, "ruth", "ruth has a long passphrase")
	if first.code != 200 || first.body["status"] != "ok" {
		t.Fatalf("sign-in: %d %v", first.code, first.body)
	}

	for i := 0; i < e.handler.MaxFailures; i++ {
		e.doFrom("198.51.100.20:5555", "POST", "/api/v1/auth/login", map[string]string{"username": "ruth", "password": "not ruth's password"}, nil, nil)
	}
	if got, err := e.users.GetByID(ctx, u.ID); err != nil || !got.IsLocked(time.Now()) {
		t.Fatalf("%d wrong passwords must lock the account: %v", e.handler.MaxFailures, err)
	}
	if me := e.do("GET", "/api/v1/auth/me", nil, first.cookie, nil); me.code != 200 || me.cookie != nil {
		t.Fatalf("the signed-in session after another client's wrong passwords: %d %v, cookie cleared: %v; want 200 and the cookie kept", me.code, me.body, me.cookie != nil)
	}
	if r := login(e, "ruth", "ruth has a long passphrase"); r.code != 401 {
		t.Fatalf("a new sign-in while the account is locked: %d %v, want 401", r.code, r.body)
	}
	// Once locked_until has passed, new sign-ins work again.
	if _, err := e.sessions.db.ExecContext(ctx, e.sessions.db.Rebind(`UPDATE users SET locked_until = ? WHERE id = ?`), store.TimeArg(time.Now().Add(-time.Second)), u.ID); err != nil {
		t.Fatal(err)
	}
	if r := login(e, "ruth", "ruth has a long passphrase"); r.code != 200 {
		t.Fatalf("a sign-in after the lock passed: %d %v", r.code, r.body)
	}

	// Disabling is an administrator's decision about the account, not a
	// guess at its password: it ends the session. The status is set
	// directly, without the admin API's own revocation, so the middleware
	// is what refuses.
	if err := e.users.Update(ctx, u.ID, "ruth", "", user.StatusDisabled); err != nil {
		t.Fatal(err)
	}
	if me := e.do("GET", "/api/v1/auth/me", nil, first.cookie, nil); me.code != 401 || me.cookie == nil || me.cookie.MaxAge >= 0 {
		t.Fatalf("a disabled account's session: %d %v, cookie %+v; want 401 and the cookie cleared", me.code, me.body, me.cookie)
	}
}

// TestSessionCheckOutageKeepsTheCookie: when the database cannot answer
// whether a cookie is good, the gateway does not know that it is bad. API
// and WebSocket calls get 503 unavailable and the cookie stays; any other
// path (the console's own files) loads without a principal. When the
// database answers again, the session carries on (M6).
func TestSessionCheckOutageKeepsTheCookie(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	r := e.sessionFor(t, e.bareUser(t, "sam", user.RoleUser), true)
	var principal bool
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	static := (&Middleware{Sessions: e.sessions, Users: e.users, Log: quiet}).Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, principal = FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	rename := func(from, to string) {
		t.Helper()
		if _, err := e.sessions.db.ExecContext(ctx, `ALTER TABLE `+from+` RENAME TO `+to); err != nil {
			t.Fatal(err)
		}
	}

	// The session lookup fails, then the user lookup does.
	for _, table := range []string{"auth_sessions", "user_roles"} {
		rename(table, table+"_gone")
		for _, path := range []string{"/api/v1/auth/me", "/ws/terminal"} {
			got := e.do("GET", path, nil, r.cookie, nil)
			if got.code != 503 || got.body["code"] != "unavailable" || got.cookie != nil {
				t.Fatalf("%s with %s unreadable: %d %v, cookie cleared: %v; want 503 unavailable and the cookie kept", path, table, got.code, got.body, got.cookie != nil)
			}
		}
		req := httptest.NewRequest("GET", "/assets/index.js", nil)
		req.AddCookie(r.cookie)
		rr := httptest.NewRecorder()
		static.ServeHTTP(rr, req)
		if rr.Code != 200 || principal || len(rr.Result().Cookies()) != 0 {
			t.Fatalf("a console file with %s unreadable: %d, principal %v, cookies %v; want it served anonymously with the cookie kept", table, rr.Code, principal, rr.Result().Cookies())
		}
		rename(table+"_gone", table)
		if me := e.do("GET", "/api/v1/auth/me", nil, r.cookie, nil); me.code != 200 {
			t.Fatalf("after the outage of %s the session carries on: %d %v", table, me.code, me.body)
		}
	}
}

// TestSessionCheckAbandonedIsNotAnError: a request the browser abandons
// (navigating away mid-request) cancels the session lookup. That is not an
// outage, and the gateway's log says so at Info, not Error: the browser
// end-to-end run fails on any logged error and caught this one (2026-10-30).
func TestSessionCheckAbandonedIsNotAnError(t *testing.T) {
	e := newEnv(t)
	r := e.sessionFor(t, e.bareUser(t, "ann", user.RoleUser), true)
	var logged bytes.Buffer
	mw := &Middleware{Sessions: e.sessions, Users: e.users, Log: slog.New(slog.NewTextHandler(&logged, nil))}
	h := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest("GET", "/api/v1/auth/me", nil).WithContext(ctx)
	req.AddCookie(r.cookie)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if strings.Contains(logged.String(), "level=ERROR") || !strings.Contains(logged.String(), "request abandoned by the client") {
		t.Fatalf("an abandoned request logged: %s", logged.String())
	}
}
