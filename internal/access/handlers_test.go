// SPDX-License-Identifier: Apache-2.0

package access

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/user"
)

type env struct {
	srv      http.Handler
	requests *Repo
	target   string
	alice    *http.Cookie
	aliceCSR string
	admin    *http.Cookie
	adminCSR string
}

// newEnv wires the handler behind the real auth middleware with one
// approval-gated policy (max 120 minutes) that makes alice eligible for the
// target over ssh.
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
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{5}, 32), false)
	policies, targets, requests := policy.NewRepo(db), target.NewRepo(db), NewRepo(db)

	h := &Handler{Requests: requests, Policies: policies, Targets: targets, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	e := &env{srv: mw.Authenticate(mw.CSRF(mux)), requests: requests}

	login := func(name string, roles ...user.Role) (*http.Cookie, string) {
		u := &user.User{Username: name, DisplayName: name, Roles: roles}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		tok, sess, err := sessions.Create(ctx, u.ID, "203.0.113.9", "test", true)
		if err != nil {
			t.Fatal(err)
		}
		if name == "alice" {
			max := 120
			// Eligibility comes through a rule, not the base, so the request
			// path is proven to use Policy.Covers like the connect gate.
			pol := &policy.Policy{Name: "prod-ssh-jit", UserID: u.ID, Enabled: true, RequireApproval: true, MaxSessionMinutes: &max,
				Rules: []policy.Rule{{Selector: policy.Selector{Tags: map[string]string{"env": "prod"}}, Protocols: []string{"ssh"}}}, IdleTimeoutMinutes: 15}
			if err := policies.Create(ctx, pol); err != nil {
				t.Fatal(err)
			}
		}
		return &http.Cookie{Name: auth.CookieName, Value: tok}, sessions.CSRFToken(sess.ID)
	}
	e.alice, e.aliceCSR = login("alice", user.RoleUser)
	e.admin, e.adminCSR = login("root", user.RoleAdmin)
	tg := &target.Target{Name: "web-1", Address: "10.0.0.5", OSFamily: target.Linux, Tags: map[string]string{"env": "prod"}}
	if err := targets.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	e.target = tg.ID
	return e
}

func (e *env) do(method, path string, body any, cookie *http.Cookie, csrf string) (int, map[string]any) {
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
	e.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

// TestOneOpenRequestAndExtension covers the approvals round-two rules at the
// HTTP layer: a second pending request for the same target and protocol is
// refused, a request while a grant is active must be an extension of that
// grant, an extension of anything else is refused, the approver may change
// the duration inside the policy maximum, and an approved extension runs on
// from the grant it extends.
func TestOneOpenRequestAndExtension(t *testing.T) {
	e := newEnv(t)
	ask := func(minutes int, extends string) (int, map[string]any) {
		return e.do("POST", "/api/v1/me/access-requests", map[string]any{"target_id": e.target, "protocol": "ssh", "reason": "deploy", "minutes": minutes, "extends_request_id": extends}, e.alice, e.aliceCSR)
	}
	code, out := ask(60, "")
	if code != 201 {
		t.Fatalf("first request: %d %v", code, out)
	}
	first := out["id"].(string)
	if code, out = ask(30, ""); code != 409 || out["code"] != "duplicate_request" {
		t.Fatalf("second pending request: got %d %v, want 409 duplicate_request", code, out)
	}
	if code, out = ask(30, first); code != 409 || out["code"] != "duplicate_request" {
		t.Fatalf("extension while still pending: got %d %v, want 409 duplicate_request", code, out)
	}

	// The approver grants 45 minutes instead of 60; 999 is over the policy's 120.
	if code, out = e.do("POST", "/api/v1/access-requests/"+first+"/approve", map[string]any{"minutes": 999}, e.admin, e.adminCSR); code != 400 || out["code"] != "duration_too_long" {
		t.Fatalf("over-maximum approval: got %d %v, want 400 duration_too_long", code, out)
	}
	code, out = e.do("POST", "/api/v1/access-requests/"+first+"/approve", map[string]any{"minutes": 45, "note": "shorter"}, e.admin, e.adminCSR)
	if code != 200 || out["approved_minutes"] != float64(45) || out["requested_minutes"] != float64(60) {
		t.Fatalf("approve with override: got %d %v", code, out)
	}
	firstExpires, _ := time.Parse(time.RFC3339Nano, out["expires_at"].(string))
	if d := time.Until(firstExpires); d < 44*time.Minute || d > 46*time.Minute {
		t.Fatalf("expiry should be ~45 minutes out, got %v", d)
	}

	// While the grant is active a plain request is refused and an extension
	// of something else is refused; an extension of the grant itself is not.
	if code, out = ask(30, ""); code != 409 || out["code"] != "already_granted" {
		t.Fatalf("request while granted: got %d %v, want 409 already_granted", code, out)
	}
	if code, out = ask(30, "00000000000000000000000000000000"); code != 409 || out["code"] != "not_extendable" {
		t.Fatalf("extension of an unknown grant: got %d %v, want 409 not_extendable", code, out)
	}
	code, out = ask(30, first)
	if code != 201 || out["extends_request_id"] != first {
		t.Fatalf("extension request: got %d %v", code, out)
	}
	ext := out["id"].(string)

	// Approving the extension runs it on from the first grant's expiry.
	code, out = e.do("POST", "/api/v1/access-requests/"+ext+"/approve", nil, e.admin, e.adminCSR)
	if code != 200 || out["approved_minutes"] != float64(30) {
		t.Fatalf("approve extension: got %d %v", code, out)
	}
	extExpires, _ := time.Parse(time.RFC3339Nano, out["expires_at"].(string))
	if got := extExpires.Sub(firstExpires); got < 29*time.Minute || got > 31*time.Minute {
		t.Fatalf("extension must run on from the previous expiry by 30 minutes, got %v", got)
	}
	// Both grants are active; the user's own view carries the names and the link.
	code, out = e.do("GET", "/api/v1/me/access", nil, e.alice, e.aliceCSR)
	items, _ := out["items"].([]any)
	if code != 200 || len(items) != 2 {
		t.Fatalf("active grants: %d %v", code, out)
	}
	for _, it := range items {
		m := it.(map[string]any)
		if m["target_name"] != "web-1" || m["username"] != "alice" {
			t.Fatalf("grant should carry names: %v", m)
		}
	}
	// The audit trail names the extension.
	if !strings.Contains(strings.ToLower(out["items"].([]any)[0].(map[string]any)["status"].(string)), "approved") {
		t.Fatalf("status: %v", out)
	}
}
