// SPDX-License-Identifier: Apache-2.0

package recstorage

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestRoutesRequireAdmin: every recording-storage route is wired to the
// admin guard (review Q1, finding 4); the configuration holds an access key
// secret, and move and test act on the bucket.
func TestRoutesRequireAdmin(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	m := h.manager(nil)
	if err := m.Load(ctx); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(h.db)
	sessions := auth.NewSessions(h.db, bytes.Repeat([]byte{9}, 32), false)
	mux := http.NewServeMux()
	(&Handler{Manager: m, Audit: audit.NewLog(h.db), Log: log}).Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	srv := mw.Authenticate(mw.CSRF(mux))
	login := func(name string, role user.Role) (*http.Cookie, string) {
		u := &user.User{Username: name, DisplayName: name, Roles: []user.Role{role}}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		tok, sess, err := sessions.Create(ctx, u.ID, "203.0.113.9", "test", true)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: auth.CookieName, Value: tok}, sessions.CSRFToken(sess.ID)
	}
	plain, pCSRF := login("alice", user.RoleUser)
	auditor, rCSRF := login("rita", user.RoleAuditor)
	admin, aCSRF := login("root", user.RoleAdmin)
	do := func(method, path string, c *http.Cookie, csrf string) int {
		req := httptest.NewRequest(method, path, bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.RemoteAddr = "203.0.113.9:4321"
		if c != nil {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		return rr.Code
	}
	routes := []struct{ method, path string }{
		{"GET", "/api/v1/admin/storage"}, {"PUT", "/api/v1/admin/storage"}, {"DELETE", "/api/v1/admin/storage"},
		{"POST", "/api/v1/admin/storage/test"}, {"POST", "/api/v1/admin/storage/move"},
	}
	for _, rt := range routes {
		if code := do(rt.method, rt.path, nil, ""); code != 401 {
			t.Errorf("%s %s anonymous: %d, want 401", rt.method, rt.path, code)
		}
		if code := do(rt.method, rt.path, plain, pCSRF); code != 403 {
			t.Errorf("%s %s as a user: %d, want 403", rt.method, rt.path, code)
		}
		if code := do(rt.method, rt.path, auditor, rCSRF); code != 403 {
			t.Errorf("%s %s as an auditor: %d, want 403", rt.method, rt.path, code)
		}
	}
	if code := do("GET", "/api/v1/admin/storage", admin, aCSRF); code != 200 {
		t.Errorf("status as an administrator: %d, want 200", code)
	}
}
