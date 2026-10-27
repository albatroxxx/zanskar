// SPDX-License-Identifier: Apache-2.0

package credential

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestRoutesRequireAdmin: every credential route is wired to the admin guard;
// the package had no 403 assertion at all, so a route registered without
// the guard would have passed every test (review Q1, finding 4).
func TestRoutesRequireAdmin(t *testing.T) {
	e := newHandlerEnv(t)
	ctx := context.Background()
	users := user.NewRepo(e.db)
	sessions := auth.NewSessions(e.db, bytes.Repeat([]byte{2}, 32), false)
	login := func(name string, role user.Role) (*http.Cookie, string) {
		u := &user.User{Username: name, DisplayName: name, Roles: []user.Role{role}}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		tok, sess, err := sessions.Create(ctx, u.ID, "127.0.0.1", "test", true)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: auth.CookieName, Value: tok}, sessions.CSRFToken(sess.ID)
	}
	plain, pCSRF := login("alice", user.RoleUser)
	auditor, rCSRF := login("rita", user.RoleAuditor)
	do := func(method, path string, c *http.Cookie, csrf string) int {
		req := httptest.NewRequest(method, path, bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		if c != nil {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		e.srv.ServeHTTP(rr, req)
		return rr.Code
	}
	routes := []struct{ method, path string }{
		{"GET", "/api/v1/credentials"}, {"POST", "/api/v1/credentials"}, {"POST", "/api/v1/credentials/generate-ssh-key"},
		{"GET", "/api/v1/credentials/x"}, {"PUT", "/api/v1/credentials/x"}, {"PATCH", "/api/v1/credentials/x"}, {"DELETE", "/api/v1/credentials/x"},
		{"POST", "/api/v1/credentials/x/rotate"}, {"POST", "/api/v1/credentials/x/rotate/cut-over"}, {"DELETE", "/api/v1/credentials/x/rotate"},
		{"POST", "/api/v1/credentials/x/rotate/retire"},
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
		if code := do(rt.method, rt.path, e.cookie, e.csrf); code == 401 || code == 403 {
			t.Errorf("%s %s as an administrator: %d, must pass the guard", rt.method, rt.path, code)
		}
	}
}
