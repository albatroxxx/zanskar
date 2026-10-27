// SPDX-License-Identifier: Apache-2.0

package group

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

// TestRoutesRequireAdmin: every group route is wired to the admin guard, so
// an anonymous caller gets 401 and a user or an auditor 403 (review Q1,
// finding 4: the guard is tested in auth, the wiring was not tested here).
func TestRoutesRequireAdmin(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{3}, 32), false)
	h := &AdminHandler{Groups: NewRepo(db), Audit: audit.NewLog(db), Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	srv := mw.Authenticate(mw.CSRF(mux))
	login := func(name string, role user.Role) (*http.Cookie, string) {
		u := &user.User{Username: name, DisplayName: name, Roles: []user.Role{role}}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		tok, sess, err := sessions.Create(ctx, u.ID, "127.0.0.1", "t", true)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: auth.CookieName, Value: tok}, sessions.CSRFToken(sess.ID)
	}
	admin, aCSRF := login("root", user.RoleAdmin)
	plain, pCSRF := login("alice", user.RoleUser)
	auditor, rCSRF := login("rita", user.RoleAuditor)
	routes := []struct{ method, path string }{
		{"GET", "/api/v1/groups"}, {"POST", "/api/v1/groups"}, {"GET", "/api/v1/groups/x"}, {"PUT", "/api/v1/groups/x"},
		{"DELETE", "/api/v1/groups/x"}, {"GET", "/api/v1/groups/x/members"}, {"PUT", "/api/v1/groups/x/members"},
	}
	do := func(method, path string, c *http.Cookie, csrf string) int {
		req := httptest.NewRequest(method, path, bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.RemoteAddr = "127.0.0.1:1"
		if c != nil {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		return rr.Code
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
		if code := do(rt.method, rt.path, admin, aCSRF); code == 401 || code == 403 {
			t.Errorf("%s %s as an administrator: %d, must pass the guard", rt.method, rt.path, code)
		}
	}
}
