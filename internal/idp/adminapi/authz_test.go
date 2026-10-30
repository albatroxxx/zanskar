// SPDX-License-Identifier: Apache-2.0

package adminapi

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
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/idp"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestRoutesRequireAdmin: every identity-provider route is wired to the
// admin guard (review Q1, finding 4). The provider rows hold bind
// credentials and client secrets, so a user or an auditor reaching them is
// the case to refuse.
func TestRoutesRequireAdmin(t *testing.T) {
	ctx := context.Background()
	db := storetest.Open(t)
	kek, _ := crypto.NewLocalKEK(bytes.Repeat([]byte{7}, 32))
	ring, err := keyring.Open(ctx, db, kek)
	if err != nil {
		t.Fatal(err)
	}
	defer ring.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{2}, 32), false)
	h := &AdminHandler{Providers: idp.NewRepo(db, ring), Audit: audit.NewLog(db), Log: log}
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
		req := httptest.NewRequest(method, path, bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		if c != nil {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		return rr.Code
	}
	routes := []struct{ method, path string }{
		{"GET", "/api/v1/identity-providers"}, {"POST", "/api/v1/identity-providers"}, {"GET", "/api/v1/identity-providers/x"},
		{"PUT", "/api/v1/identity-providers/x"}, {"DELETE", "/api/v1/identity-providers/x"}, {"POST", "/api/v1/identity-providers/x/test"},
		{"GET", "/api/v1/identity-providers/x/sync"}, {"POST", "/api/v1/identity-providers/x/sync"},
		{"POST", "/api/v1/identity-providers/x/scim-token"}, {"DELETE", "/api/v1/identity-providers/x/scim-token"},
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
