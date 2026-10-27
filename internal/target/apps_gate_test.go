// SPDX-License-Identifier: Apache-2.0

package target

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestApplicationsRefusedUntilTheGatewayCanServeThem: an application target
// is refused with 409 apps_not_ready while AppsReady reports why (no
// wildcard certificate, say), on create and on update, and accepted once it
// does; a host target is never asked. The hook was nil in every earlier
// fixture, so a gate that always let applications through passed every
// test (review Q1, finding 1b).
func TestApplicationsRefusedUntilTheGatewayCanServeThem(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{2}, 32), false)
	readyErr := errors.New("no certificate for *.apps.test")
	asked := 0
	h := &AdminHandler{Repo: NewRepo(db), Prober: &Prober{AllowLoopback: true}, Policies: policy.NewRepo(db), Live: gateway.NewRegistry(),
		AppsReady: func() error { asked++; return readyErr }, Audit: audit.NewLog(db), Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	srv := mw.Authenticate(mw.CSRF(mux))
	admin := &user.User{Username: "admin", DisplayName: "Admin", Roles: []user.Role{user.RoleAdmin}}
	if err := users.Create(ctx, admin); err != nil {
		t.Fatal(err)
	}
	tok, sess, err := sessions.Create(ctx, admin.ID, "127.0.0.1", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(body)
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", sessions.CSRFToken(sess.ID))
		req.RemoteAddr = "127.0.0.1:1"
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: tok})
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}

	if code, out := do("POST", "/api/v1/targets", map[string]any{"name": "wiki", "app_upstream": "http://10.0.0.9:3000"}); code != 409 || out["code"] != "apps_not_ready" {
		t.Fatalf("application while not ready: %d %v", code, out)
	}
	if asked != 1 {
		t.Fatalf("the hook was asked %d times for one application, want 1", asked)
	}
	code, host := do("POST", "/api/v1/targets", map[string]any{"name": "box", "address": "10.0.0.5", "os_family": "linux"})
	if code != 201 {
		t.Fatalf("a host target is not gated: %d %v", code, host)
	}
	if asked != 1 {
		t.Fatalf("the hook must not be asked for a host target, asked %d", asked)
	}
	readyErr = nil
	code, app := do("POST", "/api/v1/targets", map[string]any{"name": "wiki", "app_upstream": "http://10.0.0.9:3000"})
	if code != 201 || app["app_upstream"] != "http://10.0.0.9:3000" {
		t.Fatalf("application once ready: %d %v", code, app)
	}
	// The gate holds on update as well: a certificate that went away
	// refuses a change to the application.
	readyErr = errors.New("certificate expired")
	if code, out := do("PUT", "/api/v1/targets/"+app["id"].(string), map[string]any{"name": "wiki", "app_upstream": "http://10.0.0.9:3001"}); code != 409 || out["code"] != "apps_not_ready" {
		t.Fatalf("application update while not ready: %d %v", code, out)
	}
	if code, _ := do("PUT", "/api/v1/targets/"+host["id"].(string), map[string]any{"name": "box", "address": "10.0.0.5", "os_family": "linux", "status": "active"}); code != 200 {
		t.Fatalf("host update is not gated: %d", code)
	}
}
