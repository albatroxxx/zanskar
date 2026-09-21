// SPDX-License-Identifier: Apache-2.0

package adminapi

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

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/idp"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

type env struct {
	srv   http.Handler
	admin *http.Cookie
	csrf  string
	repo  *idp.Repo
}

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
	kek, _ := crypto.NewLocalKEK(bytes.Repeat([]byte{7}, 32))
	ring, err := keyring.Open(ctx, db, kek)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{2}, 32), false)
	e := &env{repo: idp.NewRepo(db, ring)}
	h := &AdminHandler{Providers: e.repo, Audit: audit.NewLog(db), Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	e.srv = mw.Authenticate(mw.CSRF(mux))
	adminUser := &user.User{Username: "admin", DisplayName: "Admin", Roles: []user.Role{user.RoleAdmin}}
	if err := users.Create(ctx, adminUser); err != nil {
		t.Fatal(err)
	}
	tok, sess, err := sessions.Create(ctx, adminUser.ID, "127.0.0.1", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	e.admin = &http.Cookie{Name: auth.CookieName, Value: tok}
	e.csrf = sessions.CSRFToken(sess.ID)
	return e
}

func (e *env) do(t *testing.T, method, path string, body any) (int, map[string]any, string) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrf)
	req.AddCookie(e.admin)
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out, rr.Body.String()
}

func TestProviderCRUD(t *testing.T) {
	e := newEnv(t)
	body := map[string]any{
		"name": "Okta", "type": "oidc",
		"config": map[string]any{
			"oidc":          map[string]any{"issuer": "https://okta.example", "client_id": "cid", "client_secret": "s3cret"},
			"auto_provision": true, "default_roles": []string{"user"},
		},
	}
	code, out, raw := e.do(t, "POST", "/api/v1/identity-providers", body)
	if code != 201 || out["has_secret"] != true || strings.Contains(raw, "s3cret") {
		t.Fatalf("create: %d %s", code, raw)
	}
	id := out["id"].(string)
	if code, _, raw := e.do(t, "POST", "/api/v1/identity-providers", body); code != 409 {
		t.Fatalf("duplicate: %d %s", code, raw)
	}
	code, out, raw = e.do(t, "GET", "/api/v1/identity-providers", nil)
	if code != 200 || strings.Contains(raw, "s3cret") || len(out["items"].([]any)) != 1 {
		t.Fatalf("list: %d %s", code, raw)
	}
	code, out, raw = e.do(t, "GET", "/api/v1/identity-providers/"+id, nil)
	if code != 200 || strings.Contains(raw, "s3cret") || out["config"].(map[string]any)["oidc"].(map[string]any)["client_secret"] != "" {
		t.Fatalf("get leaks secret: %d %s", code, raw)
	}
	// Update without the secret keeps it.
	upd := map[string]any{"name": "Okta prod", "enabled": false, "config": map[string]any{
		"oidc": map[string]any{"issuer": "https://okta.example", "client_id": "cid2"}, "auto_provision": false}}
	code, out, raw = e.do(t, "PUT", "/api/v1/identity-providers/"+id, upd)
	if code != 200 || out["name"] != "Okta prod" || out["enabled"] != false || out["has_secret"] != true {
		t.Fatalf("update: %d %s", code, raw)
	}
	op, err := e.repo.Open(context.Background(), id)
	if err != nil || op.Config.OIDC.ClientSecret != "s3cret" || op.Config.OIDC.ClientID != "cid2" {
		t.Fatalf("stored secret lost: %+v %v", op, err)
	}
	if code, _, raw := e.do(t, "POST", "/api/v1/identity-providers", map[string]any{"name": "bad", "type": "ldap", "config": map[string]any{"ldap": map[string]any{"url": "ldap://x"}}}); code != 400 {
		t.Fatalf("validation: %d %s", code, raw)
	}
	if code, _, _ := e.do(t, "POST", "/api/v1/identity-providers/"+id+"/test", nil); code != 502 {
		t.Fatalf("test against unreachable issuer should be 502, got %d", code)
	}
	if code, _, _ := e.do(t, "DELETE", "/api/v1/identity-providers/"+id, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _, _ := e.do(t, "GET", "/api/v1/identity-providers/"+id, nil); code != 404 {
		t.Fatalf("after delete: %d", code)
	}
}
