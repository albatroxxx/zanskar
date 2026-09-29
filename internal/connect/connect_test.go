// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/ticket"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestReviewOnlyAccountsCannotReachTargets pins the security property from
// ADR 0006 at the HTTP layer: an account holding only auditor gets 403 on
// every route that lists targets or opens sessions, before any policy is
// consulted, while a plain user gets through (to an empty list here).
func TestReviewOnlyAccountsCannotReachTargets(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{4}, 32), false)

	h := &Handler{Targets: target.NewRepo(db), Policies: policy.NewRepo(db), Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	srv := mw.Authenticate(mw.CSRF(mux))

	login := func(name string, roles ...user.Role) (*http.Cookie, string) {
		t.Helper()
		u := &user.User{Username: name, DisplayName: name, Roles: roles}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		tok, sess, err := sessions.Create(ctx, u.ID, "203.0.113.9", "test", true)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: auth.CookieName, Value: tok}, sessions.CSRFToken(sess.ID)
	}
	do := func(method, path string, body any, cookie *http.Cookie, csrf string) (int, map[string]any) {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.RemoteAddr = "203.0.113.9:4321"
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}

	reviewer, reviewerCSRF := login("reviewer", user.RoleAuditor)
	operator, operatorCSRF := login("operator", user.RoleUser)

	routes := []struct{ method, path string }{
		{"GET", "/api/v1/me/targets"},
		{"POST", "/api/v1/connect"},
		{"GET", "/api/v1/me/autoscaling-groups/asg1/instances"},
		{"POST", "/api/v1/sessions/s1/failover"},
		{"GET", "/api/v1/sessions/s1/files"},
		{"GET", "/api/v1/sessions/s1/files/content"},
		{"POST", "/api/v1/sessions/s1/files/content"},
	}
	for _, rt := range routes {
		code, out := do(rt.method, rt.path, map[string]any{"target_id": "t1", "protocol": "ssh"}, reviewer, reviewerCSRF)
		if code != http.StatusForbidden || out["code"] != "review_only" {
			t.Errorf("%s %s as auditor-only: got %d %v, want 403 review_only", rt.method, rt.path, code, out)
		}
	}

	code, out := do("GET", "/api/v1/me/targets", nil, operator, operatorCSRF)
	if code != http.StatusOK {
		t.Fatalf("user listing targets: got %d %v, want 200", code, out)
	}
	if items, ok := out["items"].([]any); !ok || len(items) != 0 {
		t.Fatalf("user with no policies should see an empty list, got %v", out)
	}
}

// TestGuacdAddressIsReadLive: desktop sessions are refused while the guacd
// setting is empty and offered as soon as it is set, without rebuilding the
// handler, because the address is read through a function at connect time.
func TestGuacdAddressIsReadLive(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{8}, 32), false)
	guacd := ""
	h := &Handler{Targets: target.NewRepo(db), Policies: policy.NewRepo(db), Log: log, GuacdAddr: func() string { return guacd }}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	srv := mw.Authenticate(mw.CSRF(mux))
	u := &user.User{Username: "alice", DisplayName: "alice", Roles: []user.Role{user.RoleUser}}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	tok, sess, err := sessions.Create(ctx, u.ID, "203.0.113.9", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	connect := func() (int, map[string]any) {
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(map[string]any{"target_id": "missing", "protocol": "rdp"})
		req := httptest.NewRequest("POST", "/api/v1/connect", &buf)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", sessions.CSRFToken(sess.ID))
		req.RemoteAddr = "203.0.113.9:4321"
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: tok})
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}
	if code, out := connect(); code != 501 || out["code"] != "protocol_unavailable" {
		t.Fatalf("desktops off: %d %v", code, out)
	}
	guacd = "127.0.0.1:4822"
	if code, out := connect(); code != 404 || out["code"] != "not_found" {
		t.Fatalf("desktops on, the request goes on to the target lookup: %d %v", code, out)
	}
}

// TestDrainingRefusesNewSessions: while a restart drains, connect answers
// 503 restarting before any target lookup; once the drain is cancelled the
// request proceeds as before.
func TestDrainingRefusesNewSessions(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{8}, 32), false)
	draining := true
	h := &Handler{Targets: target.NewRepo(db), Policies: policy.NewRepo(db), Log: log, Draining: func() bool { return draining }}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	srv := mw.Authenticate(mw.CSRF(mux))
	u := &user.User{Username: "bob", DisplayName: "bob", Roles: []user.Role{user.RoleUser}}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	tok, sess, err := sessions.Create(ctx, u.ID, "203.0.113.9", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	connect := func() (int, map[string]any) {
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(map[string]any{"target_id": "missing", "protocol": "ssh"})
		req := httptest.NewRequest("POST", "/api/v1/connect", &buf)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", sessions.CSRFToken(sess.ID))
		req.RemoteAddr = "203.0.113.9:4321"
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: tok})
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}
	if code, out := connect(); code != 503 || out["code"] != "restarting" {
		t.Fatalf("draining: %d %v", code, out)
	}
	draining = false
	if code, out := connect(); code != 404 || out["code"] != "not_found" {
		t.Fatalf("after cancel: %d %v", code, out)
	}
	// A ticket cannot be redeemed during a drain either.
	draining = true
	req := httptest.NewRequest("GET", "/ws/terminal?ticket=whatever", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != 503 {
		t.Fatalf("redeem while draining: %d %s", rr.Code, rr.Body.String())
	}
}

// TestRetentionResolution: the target's override beats the policy's;
// without either the recording follows the global policy.
func TestRetentionResolution(t *testing.T) {
	if got := retentionDays(&endpoint{RetentionDays: 7}, policy.Decision{RetentionDays: 90}); got != 7 {
		t.Fatalf("target override: %d", got)
	}
	if got := retentionDays(&endpoint{}, policy.Decision{RetentionDays: 90}); got != 90 {
		t.Fatalf("policy: %d", got)
	}
	if retentionUntil(&ticket.Grant{}) != nil {
		t.Fatal("no retention means nil")
	}
	until := retentionUntil(&ticket.Grant{RetentionDays: 3})
	if until == nil || until.Before(time.Now().Add(71*time.Hour)) || until.After(time.Now().Add(73*time.Hour)) {
		t.Fatalf("until: %v", until)
	}
}
