// SPDX-License-Identifier: Apache-2.0

package update

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestRoutesRequireAdmin: the update status and the check are admin-only;
// the package had no handler test, so the wiring was never proved (review
// Q1, finding 4). The check route is not driven as an administrator: it
// would reach out over the network.
func TestRoutesRequireAdmin(t *testing.T) {
	ctx := context.Background()
	db := storetest.Open(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{2}, 32), false)
	h := &Handler{Checker: &Checker{Current: "1.0.0", Enabled: func() bool { return false }}, Log: log, Supervisor: func() string { return "none" }}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	srv := mw.Authenticate(mw.CSRF(mux))
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
	admin, aCSRF := login("root", user.RoleAdmin)
	plain, pCSRF := login("alice", user.RoleUser)
	auditor, rCSRF := login("rita", user.RoleAuditor)
	do := func(method, path string, c *http.Cookie, csrf string) int {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("X-CSRF-Token", csrf)
		if c != nil {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		return rr.Code
	}
	for _, rt := range []struct{ method, path string }{{"GET", "/api/v1/admin/system/update"}, {"POST", "/api/v1/admin/system/update/check"}} {
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
	if code := do("GET", "/api/v1/admin/system/update", admin, aCSRF); code != 200 {
		t.Errorf("status as an administrator: %d, want 200", code)
	}
}
