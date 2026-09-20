// SPDX-License-Identifier: Apache-2.0

package target

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
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

type env struct {
	srv   http.Handler
	db    *store.DB
	audit *audit.Log
	admin *http.Cookie
	csrf  string
	user  *http.Cookie
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := testDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{2}, 32), false)
	auditLog := audit.NewLog(db)

	h := &AdminHandler{Repo: NewRepo(db), Prober: &Prober{AllowLoopback: true}, Audit: auditLog, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	e := &env{srv: mw.Authenticate(mw.CSRF(mux)), db: db, audit: auditLog}

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

	plain := &user.User{Username: "plain", DisplayName: "Plain", Roles: []user.Role{user.RoleUser}}
	if err := users.Create(ctx, plain); err != nil {
		t.Fatal(err)
	}
	tok, _, _ = sessions.Create(ctx, plain.ID, "127.0.0.1", "test", true)
	e.user = &http.Cookie{Name: auth.CookieName, Value: tok}
	return e
}

func (e *env) do(method, path string, body any, cookie *http.Cookie) (int, map[string]any) {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrf)
	req.RemoteAddr = "203.0.113.7:1234"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func TestHandlersRequireAdmin(t *testing.T) {
	e := newEnv(t)
	if code, _ := e.do("GET", "/api/v1/targets", nil, nil); code != 401 {
		t.Fatalf("anonymous: %d", code)
	}
	if code, _ := e.do("GET", "/api/v1/targets", nil, e.user); code != 403 {
		t.Fatalf("user role: %d", code)
	}
	if code, _ := e.do("GET", "/api/v1/targets", nil, e.admin); code != 200 {
		t.Fatalf("admin: %d", code)
	}
}

func TestHandlersCreateProbeTrust(t *testing.T) {
	e := newEnv(t)
	port, want := startSSHServer(t)

	code, body := e.do("POST", "/api/v1/targets", map[string]any{
		"name": "ssh-box", "address": "127.0.0.1", "os_family": "linux",
		"ports": map[string]int{"ssh": port, "rdp": 1, "vnc": 1, "winrm": 1},
		"tags":  map[string]string{"env": "test"},
	}, e.admin)
	if code != 201 {
		t.Fatalf("create: %d %v", code, body)
	}
	id := body["id"].(string)
	if body["host_key_status"] != "unknown" {
		t.Fatalf("new target should have unknown host key, got %v", body["host_key_status"])
	}
	if code, body := e.do("POST", "/api/v1/targets", map[string]any{"name": "ssh-box", "address": "10.0.0.1", "os_family": "linux"}, e.admin); code != 409 {
		t.Fatalf("duplicate: %d %v", code, body)
	}
	if code, body := e.do("POST", "/api/v1/targets", map[string]any{"name": "bad", "address": "http://x", "os_family": "linux"}, e.admin); code != 400 {
		t.Fatalf("invalid: %d %v", code, body)
	}

	code, body = e.do("POST", "/api/v1/targets/"+id+"/probe", nil, e.admin)
	if code != 200 {
		t.Fatalf("probe: %d %v", code, body)
	}
	if body["host_key_status"] != "pending" || body["host_key_fingerprint"] != want {
		t.Fatalf("probe result: status=%v fp=%v want=%s", body["host_key_status"], body["host_key_fingerprint"], want)
	}
	caps := body["target"].(map[string]any)["capabilities"].([]any)
	if len(caps) != 1 || caps[0] != "ssh" {
		t.Fatalf("capabilities: %v", caps)
	}

	if code, body := e.do("POST", "/api/v1/targets/"+id+"/host-key/trust", map[string]string{"host_key_fingerprint": "SHA256:wrong"}, e.admin); code != 409 {
		t.Fatalf("wrong fingerprint: %d %v", code, body)
	}
	code, body = e.do("POST", "/api/v1/targets/"+id+"/host-key/trust", map[string]string{"host_key_fingerprint": want}, e.admin)
	if code != 200 || body["host_key_status"] != "trusted" {
		t.Fatalf("trust: %d %v", code, body)
	}

	// Credential mapping through the API, then the full update replaces it.
	insertCredential(t, e.db, "cred1")
	if code, body := e.do("PUT", "/api/v1/targets/"+id+"/credentials/ssh", map[string]string{"credential_id": "cred1"}, e.admin); code != 200 || body["credentials"].(map[string]any)["ssh"] != "cred1" {
		t.Fatalf("set credential: %d %v", code, body)
	}
	if code, _ := e.do("PUT", "/api/v1/targets/"+id+"/credentials/ssh", map[string]string{"credential_id": "ghost"}, e.admin); code != 422 {
		t.Fatalf("ghost credential should be 422, got %d", code)
	}
	if code, _ := e.do("DELETE", "/api/v1/targets/"+id+"/credentials/ssh", nil, e.admin); code != 204 {
		t.Fatalf("unset credential: %d", code)
	}

	code, body = e.do("GET", "/api/v1/targets?tag=env=test", nil, e.admin)
	if code != 200 || len(body["items"].([]any)) != 1 {
		t.Fatalf("list by tag: %d %v", code, body)
	}
	if code, body := e.do("GET", "/api/v1/targets?tag=env=other", nil, e.admin); code != 200 || len(body["items"].([]any)) != 0 {
		t.Fatalf("list by other tag: %d %v", code, body)
	}

	if code, _ := e.do("DELETE", "/api/v1/targets/"+id, nil, e.admin); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := e.do("GET", "/api/v1/targets/"+id, nil, e.admin); code != 404 {
		t.Fatalf("after delete: %d", code)
	}

	events, _, err := e.audit.List(context.Background(), audit.Filter{ObjectType: "target"})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, ev := range events {
		seen[ev.Action] = true
	}
	for _, a := range []string{"target.create", "target.probe", "target.hostkey.trust", "target.credential.set", "target.credential.unset", "target.delete"} {
		if !seen[a] {
			t.Errorf("missing audit action %s", a)
		}
	}
}

func TestProbeForbiddenAddressIs422(t *testing.T) {
	e := newEnv(t)
	code, body := e.do("POST", "/api/v1/targets", map[string]any{"name": "meta", "address": "169.254.169.254", "os_family": "linux"}, e.admin)
	if code != 201 {
		t.Fatalf("create: %d %v", code, body)
	}
	if code, body := e.do("POST", "/api/v1/targets/"+body["id"].(string)+"/probe", nil, e.admin); code != 422 || body["code"] != "address_forbidden" {
		t.Fatalf("expected 422 address_forbidden, got %d %v", code, body)
	}
}
