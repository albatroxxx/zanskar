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

	"strings"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

type env struct {
	srv      http.Handler
	db       *store.DB
	audit    *audit.Log
	policies *policy.Repo
	live     *gateway.Registry
	vault    *credential.Vault
	admin    *http.Cookie
	csrf     string
	user     *http.Cookie
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := testDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{2}, 32), false)
	auditLog := audit.NewLog(db)

	policies, live := policy.NewRepo(db), gateway.NewRegistry()
	kek, err := crypto.NewLocalKEK(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ring, err := keyring.Open(ctx, db, kek)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	vault := credential.NewVault(db, ring)
	h := &AdminHandler{Repo: NewRepo(db), Prober: &Prober{AllowLoopback: true}, Policies: policies, Live: live, Vault: vault, Audit: auditLog, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	e := &env{srv: mw.Authenticate(mw.CSRF(mux)), db: db, audit: auditLog, policies: policies, live: live, vault: vault}

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

// TestDeleteRefusedWhileInUse covers the admin-facing half of ADR 0019: a
// target that a policy names by id, or that has a session open, answers
// delete with 409 in_use and a message naming the blockers; a tag selector
// is not a reference; once nothing depends on it, delete retires it.
func TestDeleteRefusedWhileInUse(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	code, out := e.do("POST", "/api/v1/targets", map[string]any{"name": "web-1", "address": "10.0.0.5", "os_family": "linux"}, e.admin)
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	id := out["id"].(string)
	alice := &user.User{Username: "alice", DisplayName: "Alice", Roles: []user.Role{user.RoleUser}}
	if err := user.NewRepo(e.db).Create(ctx, alice); err != nil {
		t.Fatal(err)
	}
	pol := &policy.Policy{Name: "ops-ssh", UserID: alice.ID, Enabled: true, Selector: policy.Selector{Targets: []string{id}}, Protocols: []string{"ssh"}, IdleTimeoutMinutes: 15}
	if err := e.policies.Create(ctx, pol); err != nil {
		t.Fatal(err)
	}

	code, out = e.do("DELETE", "/api/v1/targets/"+id, nil, e.admin)
	if code != 409 || out["code"] != "in_use" || !strings.Contains(out["message"].(string), "policy ops-ssh names it") {
		t.Fatalf("delete while a policy names it: %d %v", code, out)
	}

	// A tag selector matches by tags, not by id, so it does not pin the target.
	pol.Selector = policy.Selector{Tags: map[string]string{"env": "prod"}}
	if err := e.policies.Update(ctx, pol); err != nil {
		t.Fatal(err)
	}
	e.live.Add(ctx, gateway.Live{SessionID: "s1", UserID: alice.ID, TargetID: id, Protocol: "ssh"})
	code, out = e.do("DELETE", "/api/v1/targets/"+id, nil, e.admin)
	if code != 409 || !strings.Contains(out["message"].(string), "1 session is open on it") {
		t.Fatalf("delete while a session is open: %d %v", code, out)
	}
	e.live.Remove("s1")

	if code, out = e.do("DELETE", "/api/v1/targets/"+id, nil, e.admin); code != 204 {
		t.Fatalf("delete once free: %d %v", code, out)
	}
	if code, _ = e.do("GET", "/api/v1/targets/"+id, nil, e.admin); code != 404 {
		t.Fatalf("retired target must be gone from the API: %d", code)
	}
}

// TestDatabaseEnginesEnrol pins the rule that the gateway advertises exactly
// the engines it can serve: PostgreSQL, MySQL and MariaDB enrol (in any
// case), an unknown engine is refused by validation.
func TestDatabaseEnginesEnrol(t *testing.T) {
	e := newEnv(t)
	body := func(engine string) map[string]any {
		return map[string]any{"name": "db-" + engine, "address": "10.0.1.10", "os_family": "other", "engine": engine, "engine_version": "8", "tls_mode": "require"}
	}
	for _, engine := range []string{"postgres", "mysql", "mariadb", "MariaDB"} {
		code, out := e.do("POST", "/api/v1/targets", body(engine), e.admin)
		if code != 201 || out["engine"] != strings.ToLower(engine) {
			t.Fatalf("%s: got %d %v, want 201", engine, code, out)
		}
	}
	if code, out := e.do("POST", "/api/v1/targets", body("oracle"), e.admin); code != 400 {
		t.Fatalf("oracle: got %d %v, want 400", code, out)
	}
}

// TestListFiltersAndUserSuppliedSlot: the list narrows by kind, status and
// a name/address substring; binding the user_supplied sentinel makes (once)
// and reuses the shared prompt credential.
func TestListFiltersAndUserSuppliedSlot(t *testing.T) {
	e := newEnv(t)
	mk := func(body map[string]any) string {
		code, out := e.do("POST", "/api/v1/targets", body, e.admin)
		if code != 201 {
			t.Fatalf("create %v: %d %v", body, code, out)
		}
		return out["id"].(string)
	}
	host := mk(map[string]any{"name": "web-01", "address": "10.0.1.10", "os_family": "linux"})
	mk(map[string]any{"name": "win-01", "address": "10.0.1.11", "os_family": "windows", "status": "disabled"})
	db := mk(map[string]any{"name": "orders-db", "address": "orders.db.internal", "os_family": "other", "engine": "postgres", "tls_mode": "require"})
	names := func(query string) []string {
		code, out := e.do("GET", "/api/v1/targets"+query, nil, e.admin)
		if code != 200 {
			t.Fatalf("list %s: %d %v", query, code, out)
		}
		var ns []string
		for _, it := range out["items"].([]any) {
			ns = append(ns, it.(map[string]any)["name"].(string))
		}
		return ns
	}
	if got := names("?kind=database"); len(got) != 1 || got[0] != "orders-db" {
		t.Fatalf("kind=database: %v", got)
	}
	if got := names("?kind=host"); len(got) != 2 {
		t.Fatalf("kind=host: %v", got)
	}
	if got := names("?kind=host&status=active"); len(got) != 1 || got[0] != "web-01" {
		t.Fatalf("active hosts: %v", got)
	}
	if got := names("?q=ORDERS"); len(got) != 1 || got[0] != "orders-db" {
		t.Fatalf("q: %v", got)
	}
	if got := names("?q=10.0.1"); len(got) != 2 {
		t.Fatalf("q by address: %v", got)
	}
	if code, _ := e.do("GET", "/api/v1/targets?kind=printer", nil, e.admin); code != 400 {
		t.Fatalf("bad kind: %d", code)
	}

	code, out := e.do("PUT", "/api/v1/targets/"+db+"/credentials/database", map[string]string{"credential_id": "user_supplied"}, e.admin)
	if code != 200 {
		t.Fatalf("sentinel bind: %d %v", code, out)
	}
	first := out["credentials"].(map[string]any)["database"].(string)
	if first == "" || first == "user_supplied" {
		t.Fatalf("sentinel must resolve to a credential id, got %q", first)
	}
	code, out = e.do("PUT", "/api/v1/targets/"+host+"/credentials/ssh", map[string]string{"credential_id": "user_supplied"}, e.admin)
	if code != 200 || out["credentials"].(map[string]any)["ssh"] != first {
		t.Fatalf("sentinel must reuse the shared credential: %d %v", code, out)
	}
	if c, err := e.vault.Get(context.Background(), first); err != nil || c.Mode != credential.ModeUserSupplied {
		t.Fatalf("shared credential: %+v %v", c, err)
	}
}
