// SPDX-License-Identifier: Apache-2.0

package target

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// raw sends body verbatim, for requests that must not be valid JSON.
func (e *env) raw(method, path, body string) (int, map[string]any) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrf)
	req.RemoteAddr = "203.0.113.7:1234"
	req.AddCookie(e.admin)
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

// mkTarget enrols a target through the API and returns its id.
func (e *env) mkTarget(t *testing.T, body map[string]any) string {
	t.Helper()
	code, out := e.do("POST", "/api/v1/targets", body, e.admin)
	if code != 201 {
		t.Fatalf("create %v: %d %v", body, code, out)
	}
	return out["id"].(string)
}

// closedDB is a migrated database that has been closed, so every query on it
// fails the way a lost database connection would.
func closedDB(t *testing.T) *store.DB {
	t.Helper()
	db := testDB(t)
	_ = db.Close()
	return db
}

// direct calls one handler method without the auth middleware, for the
// paths that need a broken dependency the shared env cannot provide.
func direct(fn http.HandlerFunc, method, path string, values map[string]string) (int, map[string]any) {
	req := httptest.NewRequest(method, path, nil)
	for k, v := range values {
		req.SetPathValue(k, v)
	}
	rr := httptest.NewRecorder()
	fn(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func auditActions(t *testing.T, e *env, action string) []audit.Event {
	t.Helper()
	events, _, err := e.audit.List(context.Background(), audit.Filter{Action: action})
	if err != nil {
		t.Fatal(err)
	}
	return events
}

// TestListRejectsBadFilters: a tag filter without "=" or with an empty key,
// and an unknown status, are 400s that say what is wrong.
func TestListRejectsBadFilters(t *testing.T) {
	e := newEnv(t)
	for _, q := range []string{"?tag=env", "?tag==prod"} {
		code, out := e.do("GET", "/api/v1/targets"+q, nil, e.admin)
		if code != 400 || out["message"] != "tag filter must be key=value" {
			t.Fatalf("%s: %d %v", q, code, out)
		}
	}
	code, out := e.do("GET", "/api/v1/targets?status=retired", nil, e.admin)
	if code != 400 || out["message"] != "status must be active or disabled" {
		t.Fatalf("bad status: %d %v", code, out)
	}
	code, out = e.do("GET", "/api/v1/targets?kind=printer", nil, e.admin)
	if code != 400 || out["message"] != "kind must be host or database" {
		t.Fatalf("bad kind: %d %v", code, out)
	}
}

// TestCreateUpdateErrors: malformed bodies are 400, updating a missing
// target is 404, a validation failure is 400 with the reason stripped of its
// package prefix, and none of them change the stored target or write a
// success audit row.
func TestCreateUpdateErrors(t *testing.T) {
	e := newEnv(t)
	if code, out := e.raw("POST", "/api/v1/targets", "{"); code != 400 || out["code"] != "bad_request" {
		t.Fatalf("create malformed: %d %v", code, out)
	}
	id := e.mkTarget(t, map[string]any{"name": "web-1", "address": "10.0.0.5", "os_family": "linux"})

	if code, out := e.raw("PUT", "/api/v1/targets/"+id, "not json"); code != 400 || out["code"] != "bad_request" {
		t.Fatalf("update malformed: %d %v", code, out)
	}
	code, out := e.do("PUT", "/api/v1/targets/no-such-id", map[string]any{"name": "x", "address": "10.0.0.9", "os_family": "linux"}, e.admin)
	if code != 404 || out["code"] != "not_found" || out["message"] != "target not found" {
		t.Fatalf("update missing: %d %v", code, out)
	}
	code, out = e.do("PUT", "/api/v1/targets/"+id, map[string]any{"name": "web-1", "address": "http://bad", "os_family": "linux"}, e.admin)
	if code != 400 || out["code"] != "bad_request" {
		t.Fatalf("update invalid: %d %v", code, out)
	}
	if msg, _ := out["message"].(string); msg == "" || strings.HasPrefix(msg, "target: invalid") {
		t.Fatalf("validation message should drop the package prefix: %q", msg)
	}

	if code, out = e.do("GET", "/api/v1/targets/"+id, nil, e.admin); code != 200 || out["address"] != "10.0.0.5" {
		t.Fatalf("stored target must be unchanged: %d %v", code, out)
	}
	if ev := auditActions(t, e, "target.update"); len(ev) != 0 {
		t.Fatalf("failed updates must not be audited as updates: %v", ev)
	}
}

// TestDeleteMissingAndManyBlockers: deleting an unknown id is 404; a target
// named by two policies with two open sessions names them all in the 409,
// and the refusal is audited as a failure with reason in_use.
func TestDeleteMissingAndManyBlockers(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if code, out := e.do("DELETE", "/api/v1/targets/no-such-id", nil, e.admin); code != 404 || out["code"] != "not_found" {
		t.Fatalf("delete missing: %d %v", code, out)
	}
	id := e.mkTarget(t, map[string]any{"name": "db-host", "address": "10.0.0.6", "os_family": "linux"})
	alice := &user.User{Username: "alice", DisplayName: "Alice", Roles: []user.Role{user.RoleUser}}
	if err := user.NewRepo(e.db).Create(ctx, alice); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ops-a", "ops-b"} {
		pol := &policy.Policy{Name: name, UserID: alice.ID, Enabled: true, Selector: policy.Selector{Targets: []string{id}}, Protocols: []string{"ssh"}, IdleTimeoutMinutes: 15}
		if err := e.policies.Create(ctx, pol); err != nil {
			t.Fatal(err)
		}
	}
	e.live.Add(ctx, gateway.Live{SessionID: "s1", UserID: alice.ID, TargetID: id, Protocol: "ssh"})
	e.live.Add(ctx, gateway.Live{SessionID: "s2", UserID: alice.ID, TargetID: id, Protocol: "ssh"})
	e.live.Add(ctx, gateway.Live{SessionID: "s3", UserID: alice.ID, TargetID: "other", Protocol: "ssh"})

	code, out := e.do("DELETE", "/api/v1/targets/"+id, nil, e.admin)
	msg, _ := out["message"].(string)
	if code != 409 || out["code"] != "in_use" || !strings.Contains(msg, "policies ") || !strings.Contains(msg, "ops-a") ||
		!strings.Contains(msg, "ops-b") || !strings.Contains(msg, "2 sessions are open on it") {
		t.Fatalf("delete with many blockers: %d %v", code, out)
	}
	ev := auditActions(t, e, "target.delete")
	if len(ev) != 1 || ev[0].Outcome != audit.Failure || !strings.Contains(string(ev[0].Details), `"reason":"in_use"`) {
		t.Fatalf("refused delete audit: %+v", ev)
	}
	if code, _ := e.do("GET", "/api/v1/targets/"+id, nil, e.admin); code != 200 {
		t.Fatalf("refused delete must keep the target: %d", code)
	}
}

func TestInUseMessage(t *testing.T) {
	cases := []struct {
		policies []string
		open     int
		want     string
	}{
		{nil, 0, ""},
		{[]string{"a"}, 0, "the target is still in use: policy a names it. Remove it from those policies and end the sessions, then delete again."},
		{[]string{"a", "b"}, 0, "the target is still in use: policies a, b name it. Remove it from those policies and end the sessions, then delete again."},
		{nil, 1, "the target is still in use: 1 session is open on it. Remove it from those policies and end the sessions, then delete again."},
		{[]string{"a"}, 3, "the target is still in use: policy a names it; 3 sessions are open on it. Remove it from those policies and end the sessions, then delete again."},
	}
	for _, c := range cases {
		if got := InUseMessage("target", c.policies, c.open); got != c.want {
			t.Errorf("InUseMessage(%v, %d) = %q, want %q", c.policies, c.open, got, c.want)
		}
	}
	if got := InUseMessage("autoscaling group", nil, 2); !strings.HasPrefix(got, "the autoscaling group is still in use: 2 sessions") {
		t.Errorf("kind must be named: %q", got)
	}
}

// TestDeletePolicyLookupFailure: when the policy store cannot be read the
// delete is refused with a 500 and the target stays enrolled; it is never
// retired on the assumption that nothing references it.
func TestDeletePolicyLookupFailure(t *testing.T) {
	db := testDB(t)
	var logs bytes.Buffer
	repo := NewRepo(db)
	tg := &Target{Name: "keep-me", Address: "10.0.0.7", OSFamily: Linux}
	if err := repo.Create(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	h := &AdminHandler{Repo: repo, Policies: policy.NewRepo(closedDB(t)), Log: slog.New(slog.NewTextHandler(&logs, nil))}
	code, out := direct(h.delete, "DELETE", "/api/v1/targets/"+tg.ID, map[string]string{"id": tg.ID})
	if code != 500 || out["code"] != "internal" || out["message"] != "internal error" {
		t.Fatalf("delete with broken policy store: %d %v", code, out)
	}
	if _, err := repo.Get(context.Background(), tg.ID); err != nil {
		t.Fatalf("target must survive a failed delete: %v", err)
	}
	if !strings.Contains(logs.String(), "target handler") || !strings.Contains(logs.String(), "/api/v1/targets/"+tg.ID) {
		t.Fatalf("server error must be logged with its path: %s", logs.String())
	}
}

// TestStoreFailureIsOpaque500: a database error on list or get answers 500
// "internal error" without leaking the driver message, and is logged.
func TestStoreFailureIsOpaque500(t *testing.T) {
	var logs bytes.Buffer
	h := &AdminHandler{Repo: NewRepo(closedDB(t)), Log: slog.New(slog.NewTextHandler(&logs, nil))}
	for name, fn := range map[string]http.HandlerFunc{"list": h.list, "get": h.get} {
		logs.Reset()
		code, out := direct(fn, "GET", "/api/v1/targets/x", map[string]string{"id": "x"})
		if code != 500 || out["code"] != "internal" || out["message"] != "internal error" {
			t.Fatalf("%s: %d %v", name, code, out)
		}
		if !strings.Contains(logs.String(), "closed") {
			t.Fatalf("%s: the underlying error must reach the log: %s", name, logs.String())
		}
	}
}

// TestAuditFailureDoesNotUndoMutation: an audit store that cannot be written
// is logged, and a nil audit log is skipped; the mutation itself stands.
func TestAuditFailureDoesNotUndoMutation(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	repo := NewRepo(db)
	tg := &Target{Name: "aud", Address: "10.0.0.8", OSFamily: Linux}
	if err := repo.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	insertCredential(t, db, "c1")
	var logs bytes.Buffer
	for _, h := range []*AdminHandler{
		{Repo: repo, Audit: audit.NewLog(closedDB(t)), Log: slog.New(slog.NewTextHandler(&logs, nil))},
		{Repo: repo, Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
	} {
		if err := repo.SetCredential(ctx, tg.ID, SSH, "c1"); err != nil {
			t.Fatal(err)
		}
		code, out := direct(h.unsetCredential, "DELETE", "/x", map[string]string{"id": tg.ID, "protocol": "ssh"})
		if code != 204 {
			t.Fatalf("unset: %d %v", code, out)
		}
		got, err := repo.Get(ctx, tg.ID)
		if err != nil || got.Credentials[SSH] != "" {
			t.Fatalf("binding must be gone: %+v %v", got, err)
		}
	}
	if !strings.Contains(logs.String(), "audit record failed") || !strings.Contains(logs.String(), "target.credential.unset") {
		t.Fatalf("audit failure must be logged: %s", logs.String())
	}
}

// TestProbeErrors: probing an unknown id is 404; a name that does not
// resolve is a 502 probe_failed audited as a failure.
func TestProbeErrors(t *testing.T) {
	e := newEnv(t)
	if code, out := e.do("POST", "/api/v1/targets/no-such-id/probe", nil, e.admin); code != 404 || out["code"] != "not_found" {
		t.Fatalf("probe missing: %d %v", code, out)
	}

	db := testDB(t)
	repo := NewRepo(db)
	tg := &Target{Name: "nxdomain", Address: "box.zanskar.invalid", OSFamily: Linux}
	if err := repo.Create(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	offline := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dns offline")
	}}
	auditLog := audit.NewLog(db)
	h := &AdminHandler{Repo: repo, Prober: &Prober{Resolver: offline}, Audit: auditLog, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	code, out := direct(h.probe, "POST", "/x", map[string]string{"id": tg.ID})
	if code != 502 || out["code"] != "probe_failed" || !strings.Contains(out["message"].(string), "box.zanskar.invalid") {
		t.Fatalf("unresolvable: %d %v", code, out)
	}
	events, _, err := auditLog.List(context.Background(), audit.Filter{Action: "target.probe"})
	if err != nil || len(events) != 1 || events[0].Outcome != audit.Failure {
		t.Fatalf("failed probe audit: %+v %v", events, err)
	}
	if got, _ := repo.Get(context.Background(), tg.ID); got.LastProbedAt != nil {
		t.Fatalf("a failed probe must not record a probe time")
	}
}

// TestProbeDetectsChangedHostKey: once a host key is trusted, a probe that
// sees a different key reports the old fingerprint, moves the target to
// "changed", and writes a target.hostkey.changed failure audit row; the
// admin can then re-trust the new key.
func TestProbeDetectsChangedHostKey(t *testing.T) {
	e := newEnv(t)
	portA, fpA := startSSHServer(t)
	portB, fpB := startSSHServer(t)
	body := func(port int) map[string]any {
		return map[string]any{"name": "rekeyed", "address": "127.0.0.1", "os_family": "linux", "ports": map[string]int{"ssh": port, "rdp": 1, "vnc": 1, "winrm": 1}}
	}
	id := e.mkTarget(t, body(portA))
	if code, out := e.do("POST", "/api/v1/targets/"+id+"/probe", nil, e.admin); code != 200 || out["host_key_fingerprint"] != fpA {
		t.Fatalf("first probe: %d %v", code, out)
	}
	if code, out := e.do("POST", "/api/v1/targets/"+id+"/host-key/trust", map[string]string{"host_key_fingerprint": fpA}, e.admin); code != 200 {
		t.Fatalf("trust: %d %v", code, out)
	}
	// Same address, different port: trust is kept, so the new key is a change.
	if code, out := e.do("PUT", "/api/v1/targets/"+id, body(portB), e.admin); code != 200 || out["host_key_status"] != "trusted" {
		t.Fatalf("port change: %d %v", code, out)
	}
	code, out := e.do("POST", "/api/v1/targets/"+id+"/probe", nil, e.admin)
	if code != 200 || out["host_key_status"] != "changed" || out["host_key_fingerprint"] != fpB || out["host_key_changed_from"] != fpA {
		t.Fatalf("changed key: %d %v", code, out)
	}
	ev := auditActions(t, e, "target.hostkey.changed")
	if len(ev) != 1 || ev[0].Outcome != audit.Failure || !strings.Contains(string(ev[0].Details), fpA) || !strings.Contains(string(ev[0].Details), fpB) {
		t.Fatalf("changed audit: %+v", ev)
	}
	// Probing again does not raise a second alarm: it is already "changed".
	if code, out = e.do("POST", "/api/v1/targets/"+id+"/probe", nil, e.admin); code != 200 || out["host_key_status"] != "changed" || out["host_key_changed_from"] != nil {
		t.Fatalf("second probe: %d %v", code, out)
	}
	if code, out = e.do("POST", "/api/v1/targets/"+id+"/host-key/trust", map[string]string{"host_key_fingerprint": fpB}, e.admin); code != 200 || out["host_key_status"] != "trusted" {
		t.Fatalf("re-trust: %d %v", code, out)
	}
}

// TestTrustHostKeyErrors: malformed body and missing fingerprint are 400;
// trusting before any probe is 409 no_pending_host_key and is audited as a
// failure; an unknown id is 404.
func TestTrustHostKeyErrors(t *testing.T) {
	e := newEnv(t)
	id := e.mkTarget(t, map[string]any{"name": "fresh", "address": "10.0.0.9", "os_family": "linux"})
	path := "/api/v1/targets/" + id + "/host-key/trust"
	if code, out := e.raw("POST", path, "{"); code != 400 || out["code"] != "bad_request" {
		t.Fatalf("malformed: %d %v", code, out)
	}
	if code, out := e.do("POST", path, map[string]string{}, e.admin); code != 400 || out["message"] != "host_key_fingerprint required" {
		t.Fatalf("empty: %d %v", code, out)
	}
	if code, out := e.do("POST", path, map[string]string{"host_key_fingerprint": "SHA256:abc"}, e.admin); code != 409 || out["code"] != "no_pending_host_key" {
		t.Fatalf("nothing pending: %d %v", code, out)
	}
	if code, out := e.do("POST", "/api/v1/targets/no-such-id/host-key/trust", map[string]string{"host_key_fingerprint": "SHA256:abc"}, e.admin); code != 404 {
		t.Fatalf("missing: %d %v", code, out)
	}
	ev := auditActions(t, e, "target.hostkey.trust")
	if len(ev) != 2 {
		t.Fatalf("both refusals must be audited, got %d", len(ev))
	}
	for _, x := range ev {
		if x.Outcome != audit.Failure {
			t.Fatalf("refused trust audited as %s", x.Outcome)
		}
	}
	if code, out := e.do("GET", "/api/v1/targets/"+id, nil, e.admin); code != 200 || out["host_key_status"] != "unknown" {
		t.Fatalf("status must stay unknown: %d %v", code, out)
	}
}

// TestCredentialSlotErrors: setting a slot with a malformed body or unknown
// protocol is 400, on an unknown target 404; unsetting an unknown protocol
// is 400 and on an unknown target 404.
func TestCredentialSlotErrors(t *testing.T) {
	e := newEnv(t)
	id := e.mkTarget(t, map[string]any{"name": "slots", "address": "10.0.0.10", "os_family": "linux"})
	insertCredential(t, e.db, "c1")
	base := "/api/v1/targets/" + id + "/credentials/"
	if code, out := e.raw("PUT", base+"ssh", "{"); code != 400 || out["code"] != "bad_request" {
		t.Fatalf("set malformed: %d %v", code, out)
	}
	if code, out := e.do("PUT", base+"telnet", map[string]string{"credential_id": "c1"}, e.admin); code != 400 || !strings.Contains(out["message"].(string), "unknown protocol") {
		t.Fatalf("set unknown protocol: %d %v", code, out)
	}
	if code, out := e.do("PUT", base+"ssh", map[string]string{"credential_id": ""}, e.admin); code != 400 || !strings.Contains(out["message"].(string), "credential id required") {
		t.Fatalf("set empty credential: %d %v", code, out)
	}
	if code, out := e.do("PUT", "/api/v1/targets/no-such-id/credentials/ssh", map[string]string{"credential_id": "c1"}, e.admin); code != 404 {
		t.Fatalf("set on missing target: %d %v", code, out)
	}
	if code, out := e.do("DELETE", base+"telnet", nil, e.admin); code != 400 || out["message"] != "unknown protocol" {
		t.Fatalf("unset unknown protocol: %d %v", code, out)
	}
	if code, out := e.do("DELETE", "/api/v1/targets/no-such-id/credentials/ssh", nil, e.admin); code != 404 {
		t.Fatalf("unset on missing target: %d %v", code, out)
	}
	if ev := auditActions(t, e, "target.credential.set"); len(ev) != 0 {
		t.Fatalf("refused sets must not be audited as sets: %d", len(ev))
	}
	if ev := auditActions(t, e, "target.credential.unset"); len(ev) != 0 {
		t.Fatalf("refused unsets must not be audited as unsets: %d", len(ev))
	}
}

// TestProbeCertificateEdges: malformed body 400, unknown id 404; an
// authority with no login user signs for the caller's own username; a
// trusted fingerprint that no longer matches the server is reported as
// host_key_mismatch, a closed port as unreachable; a forbidden address is
// refused before any connection.
func TestProbeCertificateEdges(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	srv := startCertServer(t)
	id := e.mkTarget(t, map[string]any{"name": "ca-edge", "address": "127.0.0.1", "os_family": "linux", "ports": map[string]int{"ssh": srv.port}})
	path := "/api/v1/targets/" + id + "/probe-certificate"

	if code, out := e.raw("POST", path, "{"); code != 400 || out["code"] != "bad_request" {
		t.Fatalf("malformed: %d %v", code, out)
	}
	if code, out := e.do("POST", "/api/v1/targets/no-such-id/probe-certificate", nil, e.admin); code != 404 {
		t.Fatalf("missing: %d %v", code, out)
	}
	if code, _ := e.do("POST", "/api/v1/targets/"+id+"/probe", nil, e.admin); code != 200 {
		t.Fatalf("probe: %d", code)
	}
	if code, _ := e.do("POST", "/api/v1/targets/"+id+"/host-key/trust", map[string]string{"host_key_fingerprint": srv.fp}, e.admin); code != 200 {
		t.Fatalf("trust: %d", code)
	}
	caPEM, _ := credential.GenerateSSHKey()
	ca := &credential.Credential{Name: "ca-nouser", Type: credential.TypeSSHCA, Mode: credential.ModeVaulted}
	if err := e.vault.Create(ctx, ca, &credential.Secret{PrivateKey: caPEM}, ""); err != nil {
		t.Fatal(err)
	}
	if code, out := e.do("PUT", "/api/v1/targets/"+id+"/credentials/ssh", map[string]string{"credential_id": ca.ID}, e.admin); code != 200 {
		t.Fatalf("bind: %d %v", code, out)
	}
	srv.trust(ca.PublicKey)

	// No login user on the authority: the caller's own name is used.
	code, out := e.do("POST", path, nil, e.admin)
	if code != 200 || out["accepted"] != true || out["login_user"] != "admin" {
		t.Fatalf("caller as login user: %d %v", code, out)
	}

	// The pinned fingerprint no longer matches what the server presents.
	if _, err := e.db.ExecContext(ctx, e.db.Rebind(`UPDATE targets SET host_key_fingerprint = ? WHERE id = ?`), "SHA256:not-the-server", id); err != nil {
		t.Fatal(err)
	}
	code, out = e.do("POST", path, nil, e.admin)
	if code != 200 || out["accepted"] != false || out["reason"] != "host_key_mismatch" {
		t.Fatalf("mismatch: %d %v", code, out)
	}

	// Nothing listens on the port any more.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	if _, err := e.db.ExecContext(ctx, e.db.Rebind(`UPDATE targets SET host_key_fingerprint = ?, ports = ? WHERE id = ?`),
		srv.fp, `{"ssh":`+strconv.Itoa(closedPort)+`}`, id); err != nil {
		t.Fatal(err)
	}
	code, out = e.do("POST", path, nil, e.admin)
	if code != 200 || out["accepted"] != false || out["reason"] != "unreachable" {
		t.Fatalf("unreachable: %d %v", code, out)
	}

	ev := auditActions(t, e, "target.probe.certificate")
	reasons := map[string]audit.Outcome{}
	for _, x := range ev {
		var d struct {
			Reason    string `json:"reason"`
			LoginUser string `json:"login_user"`
		}
		_ = json.Unmarshal(x.Details, &d)
		if d.LoginUser != "admin" {
			t.Fatalf("audit login user: %s", x.Details)
		}
		reasons[d.Reason] = x.Outcome
	}
	if reasons[""] != audit.Success || reasons["host_key_mismatch"] != audit.Failure || reasons["unreachable"] != audit.Failure {
		t.Fatalf("audited outcomes: %v", reasons)
	}

	// A link-local target is refused before any login attempt.
	meta := e.mkTarget(t, map[string]any{"name": "meta", "address": "169.254.169.254", "os_family": "linux"})
	if _, err := e.db.ExecContext(ctx, e.db.Rebind(`UPDATE targets SET host_key_status = 'trusted', host_key_fingerprint = ? WHERE id = ?`), srv.fp, meta); err != nil {
		t.Fatal(err)
	}
	if code, out := e.do("PUT", "/api/v1/targets/"+meta+"/credentials/ssh", map[string]string{"credential_id": ca.ID}, e.admin); code != 200 {
		t.Fatalf("bind meta: %d %v", code, out)
	}
	if code, out := e.do("POST", "/api/v1/targets/"+meta+"/probe-certificate", nil, e.admin); code != 422 || out["code"] != "address_forbidden" {
		t.Fatalf("forbidden address: %d %v", code, out)
	}
	if n := len(auditActions(t, e, "target.probe.certificate")); n != len(ev) {
		t.Fatalf("a refused address must not be audited as a login attempt: %d vs %d", n, len(ev))
	}
}

func TestHasCapability(t *testing.T) {
	tg := &Target{Capabilities: []Protocol{SSH, RDP}}
	if !tg.HasCapability(SSH) || !tg.HasCapability(RDP) {
		t.Fatal("declared capabilities must be reported")
	}
	if tg.HasCapability(VNC) {
		t.Fatal("undeclared capability reported")
	}
	if (&Target{}).HasCapability(SSH) {
		t.Fatal("a target never probed has no capabilities")
	}
}
