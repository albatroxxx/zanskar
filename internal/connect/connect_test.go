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

	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/target"
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
