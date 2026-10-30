// SPDX-License-Identifier: Apache-2.0

package target

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	"github.com/albatroxxx/zanskar/internal/policy/policytest"
	"github.com/albatroxxx/zanskar/internal/protocol"
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
	revoker  *fakeRevoker
	requests *fakeRequests
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWith(t, &Prober{AllowLoopback: true})
}

// newEnvWith is newEnv with the address rules the test chooses.
func newEnvWith(t *testing.T, prober *Prober) *env {
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
	revoker := &fakeRevoker{}
	requests := &fakeRequests{}
	h := &AdminHandler{Repo: NewRepo(db), Prober: prober, Policies: policies, Requests: requests, Live: live, Revoker: revoker, Vault: vault, Audit: auditLog, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	e := &env{srv: mw.Authenticate(mw.CSRF(mux)), db: db, audit: auditLog, policies: policies, live: live, vault: vault, revoker: revoker, requests: requests}

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
	if code, body := e.do("POST", "/api/v1/targets", map[string]any{"name": "ssh-box", "address": "10.0.0.1", "os_family": "linux"}, e.admin); code != 409 || body["code"] != "conflict" {
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
	// A reference to something that does not exist is a bad request, worded,
	// as for autoscaling groups and policies.
	if code, body := e.do("PUT", "/api/v1/targets/"+id+"/credentials/ssh", map[string]string{"credential_id": "ghost"}, e.admin); code != 400 || body["code"] != "bad_request" || body["message"] != "credential does not exist" {
		t.Fatalf("ghost credential should be 400 bad_request, got %d %v", code, body)
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

// TestProbeForbiddenAddressIs422: the API no longer saves a forbidden literal
// (L1), but a row saved before it refused them is still refused by the probe.
func TestProbeForbiddenAddressIs422(t *testing.T) {
	e := newEnv(t)
	tg := &Target{Name: "meta", Address: "169.254.169.254", OSFamily: Linux}
	if err := NewRepo(e.db).Create(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	if code, body := e.do("POST", "/api/v1/targets/"+tg.ID+"/probe", nil, e.admin); code != 422 || body["code"] != "address_forbidden" {
		t.Fatalf("expected 422 address_forbidden, got %d %v", code, body)
	}
}

// fakeRequests stands in for the access requests: open is what it counts,
// fail makes closing them fail inside the deletion's transaction.
type fakeRequests struct {
	open   int
	closed []string
	fail   error
}

func (f *fakeRequests) OpenForTarget(_ context.Context, targetID, asgID string) (int, error) {
	return f.open, nil
}

func (f *fakeRequests) CloseForTargetTx(_ context.Context, _ *sql.Tx, targetID, asgID, note string) (int64, error) {
	if f.fail != nil {
		return 0, f.fail
	}
	f.closed = append(f.closed, targetID+asgID+":"+note)
	return int64(f.open), nil
}

// TestDeleteCascades (ADR 0036, amended 2026-10-30): deleting a target takes
// it out of the grants that name it, removes a grant left naming nothing,
// keeps a policy left with no grant, leaves tag rules alone, closes its open
// requests and ends the sessions on it, after a preview that says all of
// that. Until 1.9.0 it was refused with 409 in_use until every policy had
// been edited by hand.
func TestDeleteCascades(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	id := e.mkTarget(t, map[string]any{"name": "web-1", "address": "10.0.0.5", "os_family": "linux"})
	other := e.mkTarget(t, map[string]any{"name": "web-2", "address": "10.0.0.6", "os_family": "linux"})
	alice := &user.User{Username: "alice", DisplayName: "Alice", Roles: []user.Role{user.RoleUser}}
	if err := user.NewRepo(e.db).Create(ctx, alice); err != nil {
		t.Fatal(err)
	}
	subjects := []policy.Subject{policytest.User(alice.ID)}
	shared := policytest.Policy("shared", subjects, policytest.Named(protocol.KindHost, []string{id, other}, "ssh"))
	only := policytest.Policy("only-web-1", subjects, policytest.Named(protocol.KindHost, []string{id}, "ssh"))
	tagged := policytest.Policy("tagged", subjects, policytest.Tagged(protocol.KindHost, map[string]string{"env": "prod"}, "ssh"), policytest.Named(protocol.KindHost, []string{id}, "ssh"))
	untouched := policytest.Policy("untouched", subjects, policytest.Named(protocol.KindHost, []string{other}, "ssh"))
	for _, p := range []*policy.Policy{shared, only, tagged, untouched} {
		if err := e.policies.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	// The stored time, not Create's: the database keeps less precision than
	// a Linux clock, so the two never compare equal there.
	stored, err := e.policies.Get(ctx, untouched.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.requests.open = 2
	onWeb1 := e.live.Add(ctx, gateway.Live{SessionID: "s1", UserID: alice.ID, TargetID: id, Protocol: "ssh"})
	onWeb2 := e.live.Add(ctx, gateway.Live{SessionID: "s2", UserID: alice.ID, TargetID: other, Protocol: "ssh"})

	code, out := e.do("GET", "/api/v1/targets/"+id+"/usage", nil, e.admin)
	if code != 200 || out["live_sessions"] != float64(1) || out["open_requests"] != float64(2) {
		t.Fatalf("usage: %d %v", code, out)
	}
	pols := out["policies"].([]any)
	if len(pols) != 3 {
		t.Fatalf("usage names %d policies, want shared, only-web-1 and tagged: %v", len(pols), pols)
	}
	if p := pols[0].(map[string]any); p["name"] != "only-web-1" || p["grants_removed"] != float64(1) || p["no_grants_left"] != true {
		t.Fatalf("only-web-1 preview: %v", p)
	}

	if code, out = e.do("DELETE", "/api/v1/targets/"+id, nil, e.admin); code != 204 {
		t.Fatalf("delete: %d %v", code, out)
	}
	if code, _ = e.do("GET", "/api/v1/targets/"+id, nil, e.admin); code != 404 {
		t.Fatalf("the target must be gone: %d", code)
	}
	got := func(p *policy.Policy) *policy.Policy {
		x, err := e.policies.Get(ctx, p.ID)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	if g := got(shared).Grants; len(g) != 1 || len(g[0].Targets) != 1 || g[0].Targets[0].ID != other {
		t.Fatalf("shared keeps web-2 only: %+v", g)
	}
	if g := got(only).Grants; len(g) != 0 {
		t.Fatalf("only-web-1 is kept with no grant: %+v", g)
	}
	if g := got(tagged).Grants; len(g) != 1 || g[0].Tags == nil {
		t.Fatalf("tagged keeps its tag rule and loses the emptied grant: %+v", g)
	}
	if !got(untouched).UpdatedAt.Equal(stored.UpdatedAt) {
		t.Fatal("a policy that never named the target was rewritten")
	}
	if len(e.requests.closed) != 1 || e.requests.closed[0] != id+":target deleted" {
		t.Fatalf("requests: %v", e.requests.closed)
	}
	if !errors.Is(context.Cause(onWeb1), gateway.ErrTargetDeleted) || onWeb2.Err() != nil {
		t.Fatalf("sessions after the delete: web-1 %v, web-2 %v", context.Cause(onWeb1), onWeb2.Err())
	}
	ev := auditActions(t, e, "target.delete")
	if len(ev) != 1 || ev[0].Outcome != audit.Success || !strings.Contains(string(ev[0].Details), `"policies_updated":["only-web-1","shared","tagged"]`) ||
		!strings.Contains(string(ev[0].Details), `"sessions_ended":1`) || !strings.Contains(string(ev[0].Details), `"requests_closed":2`) {
		t.Fatalf("target.delete audit: %+v", ev)
	}
	if ups := auditActions(t, e, "policy.update"); len(ups) != 3 || !strings.Contains(string(ups[0].Details), `"removed_target":"`+id+`"`) {
		t.Fatalf("policy.update audits: %+v", ups)
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
