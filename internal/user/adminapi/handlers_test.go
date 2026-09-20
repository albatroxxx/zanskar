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
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

type fakeTOTP struct{ reset []string }

func (f *fakeTOTP) Reset(_ context.Context, id string) error {
	f.reset = append(f.reset, id)
	return nil
}

type env struct {
	srv      http.Handler
	users    *user.Repo
	sessions *auth.Sessions
	audit    *audit.Log
	totp     *fakeTOTP
	admin    *user.User
	cookie   *http.Cookie
	csrf     string
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
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := &env{
		users:    user.NewRepo(db),
		sessions: auth.NewSessions(db, bytes.Repeat([]byte{2}, 32), false),
		audit:    audit.NewLog(db),
		totp:     &fakeTOTP{},
	}
	h := &AdminHandler{Users: e.users, Sessions: e.sessions, TOTP: e.totp, Audit: e.audit, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: e.sessions, Users: e.users, Log: log}
	e.srv = mw.Authenticate(mw.CSRF(mux))

	e.admin = &user.User{Username: "root", DisplayName: "Root", Roles: []user.Role{user.RoleAdmin}}
	if err := e.users.Create(ctx, e.admin); err != nil {
		t.Fatal(err)
	}
	token, sess, err := e.sessions.Create(ctx, e.admin.ID, "127.0.0.1", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	e.cookie = &http.Cookie{Name: auth.CookieName, Value: token}
	e.csrf = e.sessions.CSRFToken(sess.ID)
	return e
}

type resp struct {
	code int
	body map[string]any
}

func (e *env) do(method, path string, body any) resp {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrf)
	req.RemoteAddr = "127.0.0.1:1"
	req.AddCookie(e.cookie)
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	out := resp{code: rr.Code}
	_ = json.Unmarshal(rr.Body.Bytes(), &out.body)
	return out
}

func TestCreateUserWithPassword(t *testing.T) {
	e := newEnv(t)
	r := e.do("POST", "/api/v1/users", map[string]any{
		"username": "Alice", "display_name": "Alice", "email": "Alice@Example.com",
		"roles": []string{"user", "auditor"}, "password": "a sufficiently long password",
	})
	if r.code != 201 {
		t.Fatalf("create: %d %v", r.code, r.body)
	}
	if _, ok := r.body["password_hash"]; ok {
		t.Fatal("password hash must not be serialised")
	}
	u, err := e.users.GetByUsername(context.Background(), "alice")
	if err != nil || !user.VerifyPassword(u.PasswordHash, "a sufficiently long password") {
		t.Fatalf("stored hash does not verify: %v", err)
	}
	if u.Email != "alice@example.com" {
		t.Fatalf("email not normalised: %q", u.Email)
	}
	events, _, _ := e.audit.List(context.Background(), audit.Filter{Action: "user.create"})
	if len(events) != 1 || !bytes.Contains(events[0].Details, []byte(`"roles_granted":["auditor"]`)) {
		t.Fatalf("expected user.create with roles_granted, got %s", events[0].Details)
	}
	if bytes.Contains(events[0].Details, []byte("sufficiently")) {
		t.Fatal("password leaked into audit details")
	}

	if r := e.do("POST", "/api/v1/users", map[string]any{"username": "alice", "display_name": "x", "roles": []string{"user"}}); r.code != 409 {
		t.Fatalf("duplicate: %d %v", r.code, r.body)
	}
	if r := e.do("POST", "/api/v1/users", map[string]any{"username": "bob", "display_name": "x", "roles": []string{"user"}, "password": "short"}); r.code != 400 {
		t.Fatalf("weak password: %d", r.code)
	}
	if r := e.do("POST", "/api/v1/users", map[string]any{"username": "bob", "display_name": "x", "roles": []string{}}); r.code != 400 {
		t.Fatalf("no roles: %d", r.code)
	}
	if r := e.do("POST", "/api/v1/users", map[string]any{"username": "bob", "display_name": "x", "roles": []string{"user"}, "extra": 1}); r.code != 400 {
		t.Fatalf("unknown field: %d", r.code)
	}
	if r := e.do("GET", "/api/v1/users?limit=1", nil); r.code != 200 || len(r.body["items"].([]any)) != 1 || r.body["next_cursor"] == nil {
		t.Fatalf("list: %d %v", r.code, r.body)
	}
}

func TestRolesAndLastAdmin(t *testing.T) {
	e := newEnv(t)
	if r := e.do("PUT", "/api/v1/users/"+e.admin.ID+"/roles", map[string]any{"roles": []string{"user"}}); r.code != 409 || r.body["code"] != "last_admin" {
		t.Fatalf("expected last_admin, got %d %v", r.code, r.body)
	}
	r := e.do("POST", "/api/v1/users", map[string]any{"username": "second", "display_name": "Second", "roles": []string{"user"}})
	id := r.body["id"].(string)
	r = e.do("PUT", "/api/v1/users/"+id+"/roles", map[string]any{"roles": []string{"user", "admin"}})
	if r.code != 200 {
		t.Fatalf("roles update: %d %v", r.code, r.body)
	}
	events, _, _ := e.audit.List(context.Background(), audit.Filter{Action: "user.roles.update"})
	if len(events) != 1 || !bytes.Contains(events[0].Details, []byte(`"roles_granted":["admin"]`)) || events[0].ActorUserID != e.admin.ID {
		t.Fatalf("roles update not audited correctly: %+v", events)
	}
	if r := e.do("GET", "/api/v1/users/nope", nil); r.code != 404 {
		t.Fatalf("404 expected, got %d", r.code)
	}
	if r := e.do("PUT", "/api/v1/users/"+e.admin.ID+"/roles", map[string]any{"roles": []string{"user"}}); r.code != 200 {
		t.Fatalf("demotion with another admin should pass: %d %v", r.code, r.body)
	}
	// Having demoted themselves, the caller is no longer an admin.
	if r := e.do("GET", "/api/v1/users", nil); r.code != 403 {
		t.Fatalf("expected 403 after self-demotion, got %d", r.code)
	}
}

func TestSelfProtectionAndDelete(t *testing.T) {
	e := newEnv(t)
	if r := e.do("DELETE", "/api/v1/users/"+e.admin.ID, nil); r.code != 409 || r.body["code"] != "self" {
		t.Fatalf("self delete: %d %v", r.code, r.body)
	}
	if r := e.do("PUT", "/api/v1/users/"+e.admin.ID, map[string]any{"status": "disabled"}); r.code != 409 || r.body["code"] != "self" {
		t.Fatalf("self disable: %d %v", r.code, r.body)
	}
	r := e.do("POST", "/api/v1/users", map[string]any{"username": "temp", "display_name": "Temp", "roles": []string{"user"}, "password": "temporary long password"})
	id := r.body["id"].(string)
	// The user has a live session; disabling revokes it.
	token, _, err := e.sessions.Create(context.Background(), id, "127.0.0.1", "x", true)
	if err != nil {
		t.Fatal(err)
	}
	if r := e.do("PUT", "/api/v1/users/"+id, map[string]any{"status": "disabled"}); r.code != 200 || r.body["status"] != "disabled" {
		t.Fatalf("disable: %d %v", r.code, r.body)
	}
	if _, err := e.sessions.Lookup(context.Background(), token); err == nil {
		t.Fatal("session should be revoked after disable")
	}
	if r := e.do("PUT", "/api/v1/users/"+id+"/password", map[string]any{"password": "another long password"}); r.code != 200 {
		t.Fatalf("password reset: %d %v", r.code, r.body)
	}
	if r := e.do("DELETE", "/api/v1/users/"+id+"/mfa", nil); r.code != 200 || len(e.totp.reset) != 1 {
		t.Fatalf("mfa reset: %d %v", r.code, r.body)
	}
	if r := e.do("DELETE", "/api/v1/users/"+id+"/sessions", nil); r.code != 200 {
		t.Fatalf("revoke sessions: %d", r.code)
	}
	if r := e.do("DELETE", "/api/v1/users/"+id, nil); r.code != 204 {
		t.Fatalf("delete: %d %v", r.code, r.body)
	}
	if r := e.do("GET", "/api/v1/users/"+id, nil); r.code != 404 {
		t.Fatalf("deleted user still readable: %d", r.code)
	}
	for _, action := range []string{"user.update", "user.password.reset", "user.mfa.reset", "user.sessions.revoke", "user.delete"} {
		if ev, _, _ := e.audit.List(context.Background(), audit.Filter{Action: action}); len(ev) == 0 {
			t.Errorf("missing audit event %s", action)
		}
	}
}

func TestNonAdminForbidden(t *testing.T) {
	e := newEnv(t)
	u := &user.User{Username: "plain", DisplayName: "Plain", Roles: []user.Role{user.RoleUser}}
	if err := e.users.Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	token, sess, _ := e.sessions.Create(context.Background(), u.ID, "127.0.0.1", "x", true)
	e.cookie = &http.Cookie{Name: auth.CookieName, Value: token}
	e.csrf = e.sessions.CSRFToken(sess.ID)
	if r := e.do("GET", "/api/v1/users", nil); r.code != 403 {
		t.Fatalf("expected 403, got %d", r.code)
	}
}
