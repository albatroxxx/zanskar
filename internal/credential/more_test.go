// SPDX-License-Identifier: Apache-2.0

package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// syncBuffer is a log sink safe for the race detector.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// newHandlerEnvWith is newHandlerEnv with a captured log and a hook to adjust
// the handler (for example to run without an audit log).
func newHandlerEnvWith(t *testing.T, adjust func(*AdminHandler)) (*env, *syncBuffer) {
	t.Helper()
	v, db := testVault(t)
	ctx := context.Background()
	logBuf := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logBuf, nil))
	users := user.NewRepo(db)
	admin := &user.User{Username: "admin", DisplayName: "Admin", Roles: []user.Role{user.RoleAdmin}}
	if err := users.Create(ctx, admin); err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{2}, 32), false)
	token, sess, err := sessions.Create(ctx, admin.ID, "127.0.0.1", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	h := &AdminHandler{Vault: v, Audit: audit.NewLog(db), Log: log}
	if adjust != nil {
		adjust(h)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	return &env{srv: mw.Authenticate(mw.CSRF(mux)), cookie: &http.Cookie{Name: auth.CookieName, Value: token}, csrf: sessions.CSRFToken(sess.ID), db: db, vault: v}, logBuf
}

// doRaw sends body verbatim, so a malformed document can be tested.
func (e *env) doRaw(method, path, body string) (int, string) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrf)
	req.AddCookie(e.cookie)
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	return rr.Code, rr.Body.String()
}

func idOf(t *testing.T, body string) string {
	t.Helper()
	var c struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &c); err != nil || c.ID == "" {
		t.Fatalf("no id in %s", body)
	}
	return c.ID
}

func auditCount(t *testing.T, db *store.DB, action string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), db.Rebind(`SELECT COUNT(*) FROM audit_events WHERE action = ?`), action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestVaultUnknownID: every vault operation on an id that does not exist
// reports ErrNotFound rather than acting on nothing or failing obscurely.
func TestVaultUnknownID(t *testing.T) {
	v, _ := testVault(t)
	ctx := context.Background()
	key, _ := GenerateSSHKey()
	ops := map[string]func() error{
		"update": func() error { _, err := v.Update(ctx, "nope", Metadata{Name: "x", Username: "u"}); return err },
		"rotate": func() error { _, err := v.Rotate(ctx, "nope", &Secret{Password: "pw-123456"}); return err },
		"delete": func() error { return v.Delete(ctx, "nope") },
		"open":   func() error { _, err := v.Open(ctx, "nope"); return err },
		"prepare": func() error {
			_, err := v.PrepareRotation(ctx, "nope", &Secret{PrivateKey: key})
			return err
		},
		"cut over":    func() error { _, err := v.CutOver(ctx, "nope"); return err },
		"cancel":      func() error { _, err := v.CancelRotation(ctx, "nope"); return err },
		"retire":      func() error { _, err := v.Retire(ctx, "nope"); return err },
		"openPending": func() error { _, err := v.OpenPending(ctx, "nope"); return err },
		"unseal":      func() error { _, err := v.unseal(ctx, "nope", false); return err },
	}
	for name, op := range ops {
		if err := op(); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s on an unknown id: %v, want ErrNotFound", name, err)
		}
	}
}

// TestVaultListPaging: the limit is clamped to the default, the cursor walks
// by name, and an empty vault lists as an empty slice (JSON [] not null).
func TestVaultListPaging(t *testing.T) {
	v, _ := testVault(t)
	ctx := context.Background()
	items, next, err := v.List(ctx, "", 10)
	if err != nil || items == nil || len(items) != 0 || next != "" {
		t.Fatalf("empty vault: %v %v %q", items, err, next)
	}
	for _, n := range []string{"c", "a", "b"} {
		if err := v.Create(ctx, &Credential{Name: n, Type: TypePassword, Mode: ModeVaulted, Username: "u"}, &Secret{Password: "pw-" + n}, ""); err != nil {
			t.Fatal(err)
		}
	}
	for _, lim := range []int{0, -1, 501} {
		items, next, err = v.List(ctx, "", lim)
		if err != nil || len(items) != 3 || next != "" {
			t.Fatalf("limit %d falls back to the default: %d items next=%q %v", lim, len(items), next, err)
		}
	}
	items, next, err = v.List(ctx, "", 2)
	if err != nil || len(items) != 2 || items[0].Name != "a" || items[1].Name != "b" || next != "b" {
		t.Fatalf("first page: %v next=%q %v", items, next, err)
	}
	items, next, err = v.List(ctx, next, 2)
	if err != nil || len(items) != 1 || items[0].Name != "c" || next != "" {
		t.Fatalf("second page: %v next=%q %v", items, next, err)
	}
}

// TestVaultUpdateRules: Update re-applies the type rules, refuses a name
// clash, and never stores a username on a mode that stores nothing.
func TestVaultUpdateRules(t *testing.T) {
	v, db := testVault(t)
	ctx := context.Background()
	pw := &Credential{Name: "pw", Type: TypePassword, Mode: ModeVaulted, Username: "root"}
	dom := &Credential{Name: "dom", Type: TypeDomain, Mode: ModeVaulted, Username: "svc", Domain: "corp"}
	ask := &Credential{Name: "ask", Type: TypePassword, Mode: ModeUserSupplied}
	for _, c := range []*Credential{pw, dom} {
		if err := v.Create(ctx, c, &Secret{Password: "pw-123456"}, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := v.Create(ctx, ask, nil, ""); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		id string
		m  Metadata
	}{
		"vaulted password without username": {pw.ID, Metadata{Name: "pw", Username: "  "}},
		"domain without domain":             {dom.ID, Metadata{Name: "dom", Username: "svc", Domain: " "}},
		"blank name":                        {pw.ID, Metadata{Name: " ", Username: "root"}},
		"name too long":                     {pw.ID, Metadata{Name: strings.Repeat("n", 256), Username: "root"}},
	} {
		if _, err := v.Update(ctx, tc.id, tc.m); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	if _, err := v.Update(ctx, pw.ID, Metadata{Name: "dom", Username: "root"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("rename onto an existing name: %v, want ErrDuplicate", err)
	}
	got, err := v.Get(ctx, pw.ID)
	if err != nil || got.Name != "pw" || got.Username != "root" {
		t.Fatalf("refused updates must not change the row: %+v %v", got, err)
	}
	got, err = v.Update(ctx, ask.ID, Metadata{Name: " ask2 ", Username: "bob"})
	if err != nil || got.Name != "ask2" || got.Username != "" {
		t.Fatalf("user_supplied keeps no username: %+v %v", got, err)
	}
	var stored *string
	if err := db.QueryRowContext(ctx, db.Rebind(`SELECT username FROM credentials WHERE id = ?`), ask.ID).Scan(&stored); err != nil || stored != nil {
		t.Fatalf("username column should be NULL, got %v %v", stored, err)
	}
}

// TestVaultRefusalsAndClosedRing: rotation refusals by type and input, and a
// closed key ring makes every sealing or unsealing step fail instead of
// storing plaintext or returning garbage.
func TestVaultRefusalsAndClosedRing(t *testing.T) {
	v, db := testVault(t)
	ctx := context.Background()
	pw := &Credential{Name: "pw", Type: TypePassword, Mode: ModeVaulted, Username: "root"}
	if err := v.Create(ctx, pw, &Secret{Password: "pw-123456"}, ""); err != nil {
		t.Fatal(err)
	}
	first, _ := GenerateSSHKey()
	next, _ := GenerateSSHKey()
	ca := &Credential{Name: "ca", Type: TypeSSHCA, Mode: ModeVaulted}
	if err := v.Create(ctx, ca, &Secret{PrivateKey: first}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Rotate(ctx, pw.ID, &Secret{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rotate to an empty password: %v", err)
	}
	if _, err := v.PrepareRotation(ctx, pw.ID, &Secret{PrivateKey: next}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("two-step rotation of a password: %v", err)
	}
	if _, err := v.PrepareRotation(ctx, ca.ID, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("prepare without a key: %v", err)
	}
	if _, err := v.PrepareRotation(ctx, ca.ID, &Secret{PrivateKey: "not a key"}); !errors.Is(err, ErrBadKey) {
		t.Fatalf("prepare with junk: %v", err)
	}
	if _, err := v.CancelRotation(ctx, ca.ID); !errors.Is(err, ErrNoRotation) {
		t.Fatalf("cancel with nothing prepared: %v", err)
	}
	if _, err := v.PrepareRotation(ctx, ca.ID, &Secret{PrivateKey: next}); err != nil {
		t.Fatal(err)
	}

	// A pending public key with no sealed key behind it (a damaged row) must
	// not open as an empty key.
	other := &Credential{Name: "ca-damaged", Type: TypeSSHCA, Mode: ModeVaulted}
	if err := v.Create(ctx, other, &Secret{PrivateKey: next}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, db.Rebind(`UPDATE credentials SET pending_public_key = ? WHERE id = ?`), ca.PublicKey, other.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := v.OpenPending(ctx, other.ID); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("pending key without ciphertext: %v, want ErrNoSecret", err)
	}

	v.ring.Close()
	if err := v.Create(ctx, &Credential{Name: "late", Type: TypePassword, Mode: ModeVaulted, Username: "u"}, &Secret{Password: "pw-late-1"}, ""); !errors.Is(err, keyring.ErrClosed) {
		t.Fatalf("create with a closed ring: %v", err)
	}
	if items, _, _ := v.List(ctx, "", 10); len(items) != 3 {
		t.Fatalf("a failed seal must not leave a row: %d rows", len(items))
	}
	if _, err := v.Rotate(ctx, pw.ID, &Secret{Password: "pw-654321"}); !errors.Is(err, keyring.ErrClosed) {
		t.Fatalf("rotate with a closed ring: %v", err)
	}
	if _, err := v.CutOver(ctx, ca.ID); !errors.Is(err, keyring.ErrClosed) {
		t.Fatalf("cut over with a closed ring: %v", err)
	}
	if _, err := v.OpenPending(ctx, ca.ID); !errors.Is(err, keyring.ErrClosed) {
		t.Fatalf("open pending with a closed ring: %v", err)
	}
	if _, err := v.CancelRotation(ctx, ca.ID); err != nil {
		t.Fatalf("cancel needs no key: %v", err)
	}
	if _, err := v.PrepareRotation(ctx, ca.ID, &Secret{PrivateKey: next}); !errors.Is(err, keyring.ErrClosed) {
		t.Fatalf("prepare with a closed ring: %v", err)
	}
	if got, _ := v.Get(ctx, ca.ID); got.Rotation != nil {
		t.Fatalf("a failed prepare must leave nothing pending: %+v", got.Rotation)
	}
}

// TestHandlerRefusals: malformed bodies, unknown ids, name clashes, in-use
// deletes and bad keys get the right status and code, record no audit event,
// and never echo the secret that was sent.
func TestHandlerRefusals(t *testing.T) {
	e := newHandlerEnv(t)
	const canary = "never-echo-this-pw-9" // made up: asserted never to come back
	secret := canary
	for _, p := range []struct{ method, path string }{
		{"POST", "/api/v1/credentials"},
		{"POST", "/api/v1/credentials/generate-ssh-key"},
		{"PATCH", "/api/v1/credentials/x"},
		{"POST", "/api/v1/credentials/x/rotate"},
	} {
		code, body := e.doRaw(p.method, p.path, `{"password":"`+secret+`"`)
		if code != 400 || strings.Contains(body, secret) {
			t.Errorf("%s %s with a truncated body: %d %s", p.method, p.path, code, body)
		}
	}
	for _, p := range []struct{ method, path string }{
		{"PATCH", "/api/v1/credentials/nope"},
		{"POST", "/api/v1/credentials/nope/rotate"},
		{"POST", "/api/v1/credentials/nope/rotate/cut-over"},
		{"DELETE", "/api/v1/credentials/nope/rotate"},
		{"POST", "/api/v1/credentials/nope/rotate/retire"},
		{"DELETE", "/api/v1/credentials/nope"},
	} {
		code, body := e.do(p.method, p.path, map[string]any{"password": secret})
		if code != 404 || !strings.Contains(body, "not_found") || strings.Contains(body, secret) {
			t.Errorf("%s %s on an unknown id: %d %s", p.method, p.path, code, body)
		}
	}

	code, body := e.do("POST", "/api/v1/credentials", map[string]any{"name": "pw", "type": "password", "mode": "vaulted", "username": "root", "password": secret})
	if code != 201 {
		t.Fatalf("create: %d %s", code, body)
	}
	pw := idOf(t, body)
	code, body = e.do("POST", "/api/v1/credentials/generate-ssh-key", map[string]any{"name": "key", "username": "deploy"})
	if code != 201 {
		t.Fatalf("generate: %d %s", code, body)
	}
	key := idOf(t, body)
	creates := auditCount(t, e.db, "credential.create")

	code, body = e.do("POST", "/api/v1/credentials/generate-ssh-key", map[string]any{"name": "pw", "username": "deploy"})
	if code != 409 || !strings.Contains(body, `"conflict"`) {
		t.Fatalf("generate onto a taken name: %d %s", code, body)
	}
	code, body = e.do("PATCH", "/api/v1/credentials/"+key, map[string]any{"name": "pw"})
	if code != 409 || !strings.Contains(body, `"conflict"`) {
		t.Fatalf("rename onto a taken name: %d %s", code, body)
	}
	code, body = e.do("POST", "/api/v1/credentials/"+pw+"/rotate", map[string]any{})
	if code != 400 || !strings.Contains(body, "password required") {
		t.Fatalf("rotate a password to nothing: %d %s", code, body)
	}
	code, body = e.do("POST", "/api/v1/credentials/"+key+"/rotate", map[string]any{"private_key": secret})
	if code != 400 || strings.Contains(body, secret) {
		t.Fatalf("rotate to junk must be refused without echoing it: %d %s", code, body)
	}
	if n := auditCount(t, e.db, "credential.create"); n != creates {
		t.Fatalf("a refused create was audited: %d -> %d", creates, n)
	}
	if n := auditCount(t, e.db, "credential.rotate") + auditCount(t, e.db, "credential.update"); n != 0 {
		t.Fatalf("refused updates or rotations were audited: %d", n)
	}

	// Bound to a target and an autoscaling group: delete is refused, the
	// counts are reported, and the row stays.
	ctx := context.Background()
	now := store.TimeArg(store.NullTime{}.Time)
	for _, q := range []string{
		`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t1', 'box', '10.0.0.1', 'linux', ?, ?)`,
		`INSERT INTO autoscaling_groups (id, name, provider, region, external_name, role_arn, external_id, os_family, created_at, updated_at) VALUES ('a1', 'fleet', 'aws', 'ap-south-1', 'fleet-asg', 'arn:aws:iam::1:role/r', 'ext', 'linux', ?, ?)`,
	} {
		if _, err := e.db.ExecContext(ctx, e.db.Rebind(q), now, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.db.ExecContext(ctx, e.db.Rebind(`INSERT INTO asg_credentials (asg_id, protocol, credential_id) VALUES ('a1', 'ssh', ?)`), pw); err != nil {
		t.Fatal(err)
	}
	code, body = e.do("GET", "/api/v1/credentials/"+pw, nil)
	if code != 200 || !strings.Contains(body, `"autoscaling_groups":1`) {
		t.Fatalf("in-use counts: %d %s", code, body)
	}
	code, body = e.do("DELETE", "/api/v1/credentials/"+pw, nil)
	if code != 409 || !strings.Contains(body, `"in_use"`) {
		t.Fatalf("delete while bound to a group: %d %s", code, body)
	}
	if _, err := e.db.ExecContext(ctx, `DELETE FROM asg_credentials`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.ExecContext(ctx, e.db.Rebind(`INSERT INTO target_credentials (target_id, protocol, credential_id) VALUES ('t1', 'ssh', ?)`), pw); err != nil {
		t.Fatal(err)
	}
	if code, body = e.do("DELETE", "/api/v1/credentials/"+pw, nil); code != 409 || !strings.Contains(body, `"in_use"`) {
		t.Fatalf("delete while bound to a target: %d %s", code, body)
	}
	if n := auditCount(t, e.db, "credential.delete"); n != 0 {
		t.Fatalf("a refused delete was audited: %d", n)
	}
	if code, _ = e.do("GET", "/api/v1/credentials/"+pw, nil); code != 200 {
		t.Fatal("refused delete removed the row")
	}
}

// TestHandlerCertificateAuthorityRefusals: rotating an authority takes a
// private key, not a password, and refuses junk; cancelling with nothing
// prepared is a conflict. The secret sent is never echoed.
func TestHandlerCertificateAuthorityRefusals(t *testing.T) {
	e := newHandlerEnv(t)
	code, body := e.do("POST", "/api/v1/credentials", map[string]any{"name": "ca", "type": "ssh_ca", "mode": "vaulted"})
	if code != 201 {
		t.Fatalf("create: %d %s", code, body)
	}
	ca := idOf(t, body)
	const secret = "ca-password-not-a-key"
	code, body = e.do("POST", "/api/v1/credentials/"+ca+"/rotate", map[string]any{"password": secret})
	if code != 400 || !strings.Contains(body, "private_key required") || strings.Contains(body, secret) {
		t.Fatalf("a password is not a next key: %d %s", code, body)
	}
	code, body = e.do("POST", "/api/v1/credentials/"+ca+"/rotate", map[string]any{"private_key": secret})
	if code != 400 || strings.Contains(body, secret) {
		t.Fatalf("junk next key: %d %s", code, body)
	}
	code, body = e.do("DELETE", "/api/v1/credentials/"+ca+"/rotate", nil)
	if code != 409 || !strings.Contains(body, "no_rotation") {
		t.Fatalf("cancel with nothing prepared: %d %s", code, body)
	}
	if n := auditCount(t, e.db, "credential.rotate.prepare") + auditCount(t, e.db, "credential.rotate.cancel"); n != 0 {
		t.Fatalf("refusals were audited: %d", n)
	}
}

// TestHandlerPrepareAuditFingerprint: the prepare audit event names the next
// key by its fingerprint and the cut-over event names both; neither carries
// key material.
func TestHandlerPrepareAuditFingerprint(t *testing.T) {
	e := newHandlerEnv(t)
	code, body := e.do("POST", "/api/v1/credentials", map[string]any{"name": "ca", "type": "ssh_ca", "mode": "vaulted"})
	if code != 201 {
		t.Fatalf("create: %d %s", code, body)
	}
	var c Credential
	_ = json.Unmarshal([]byte(body), &c)
	code, body = e.do("POST", "/api/v1/credentials/"+c.ID+"/rotate", map[string]any{})
	if code != 200 {
		t.Fatalf("prepare: %d %s", code, body)
	}
	var prepared Credential
	_ = json.Unmarshal([]byte(body), &prepared)
	if code, body = e.do("POST", "/api/v1/credentials/"+c.ID+"/rotate/cut-over", nil); code != 200 {
		t.Fatalf("cut over: %d %s", code, body)
	}
	ctx := context.Background()
	var details string
	if err := e.db.QueryRowContext(ctx, `SELECT details FROM audit_events WHERE action = 'credential.rotate.prepare'`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	want := fingerprint(prepared.Rotation.PendingPublicKey)
	if !strings.HasPrefix(want, "SHA256:") || !strings.Contains(details, want) {
		t.Fatalf("prepare details %s should name %s", details, want)
	}
	if err := e.db.QueryRowContext(ctx, `SELECT details FROM audit_events WHERE action = 'credential.rotate'`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(details, fingerprint(c.PublicKey)) || !strings.Contains(details, want) {
		t.Fatalf("cut-over details %s should name old and new fingerprints", details)
	}
	for _, d := range []string{details, body} {
		if strings.Contains(d, "PRIVATE KEY") {
			t.Fatal("key material in a response or audit detail")
		}
	}
	if fingerprint("") != "" || fingerprint("not an authorized key") != "" {
		t.Fatal("fingerprint of nothing or junk is empty")
	}
}

// TestHandlerSealFailureIsOpaque: when sealing fails (closed key ring), the
// API answers a bare 500; the password sent appears neither in the response
// nor in the server log, and nothing is stored or audited.
func TestHandlerSealFailureIsOpaque(t *testing.T) {
	e, logs := newHandlerEnvWith(t, nil)
	e.vault.ring.Close()
	const secret = "sealed-never-seen-77"
	code, body := e.do("POST", "/api/v1/credentials", map[string]any{"name": "pw", "type": "password", "mode": "vaulted", "username": "root", "password": secret})
	if code != 500 || !strings.Contains(body, `"internal"`) || strings.Contains(body, "keyring") || strings.Contains(body, secret) {
		t.Fatalf("seal failure: %d %s", code, body)
	}
	if out := logs.String(); !strings.Contains(out, "keyring: closed") || strings.Contains(out, secret) {
		t.Fatalf("log should name the cause but not the secret: %s", out)
	}
	if items, _, err := e.vault.List(context.Background(), "", 10); err != nil || len(items) != 0 {
		t.Fatalf("nothing stored: %v %v", items, err)
	}
	if n := auditCount(t, e.db, "credential.create"); n != 0 {
		t.Fatalf("a failed create was audited: %d", n)
	}
}

// TestHandlerAuditOptionalAndFailing: with no audit log the mutation still
// succeeds; with a broken audit table it succeeds and the failure is logged
// without the secret.
func TestHandlerAuditOptionalAndFailing(t *testing.T) {
	e, _ := newHandlerEnvWith(t, func(h *AdminHandler) { h.Audit = nil })
	code, body := e.do("POST", "/api/v1/credentials", map[string]any{"name": "pw", "type": "password", "mode": "vaulted", "username": "root", "password": "no-audit-pw-1"})
	if code != 201 {
		t.Fatalf("create without audit: %d %s", code, body)
	}
	if n := auditCount(t, e.db, "credential.create"); n != 0 {
		t.Fatalf("no audit log configured, yet %d events", n)
	}

	e, logs := newHandlerEnvWith(t, nil)
	if _, err := e.db.ExecContext(context.Background(), `DROP TABLE audit_events`); err != nil {
		t.Fatal(err)
	}
	const secret = "audit-broken-pw-2"
	code, body = e.do("POST", "/api/v1/credentials", map[string]any{"name": "pw", "type": "password", "mode": "vaulted", "username": "root", "password": secret})
	if code != 201 || strings.Contains(body, secret) {
		t.Fatalf("create with a broken audit table: %d %s", code, body)
	}
	out := logs.String()
	if !strings.Contains(out, "audit record failed") || !strings.Contains(out, "credential.create") || strings.Contains(out, secret) {
		t.Fatalf("audit failure log: %s", out)
	}
}

// TestHandlerListPaging: the list route pages by name with limit and cursor.
func TestHandlerListPaging(t *testing.T) {
	e := newHandlerEnv(t)
	for i := range 3 {
		code, body := e.do("POST", "/api/v1/credentials", map[string]any{"name": fmt.Sprintf("c%d", i), "type": "password", "mode": "vaulted", "username": "u", "password": "page-pw-123"})
		if code != 201 {
			t.Fatalf("create: %d %s", code, body)
		}
	}
	code, body := e.do("GET", "/api/v1/credentials?limit=2", nil)
	if code != 200 || !strings.Contains(body, `"next_cursor":"c1"`) || strings.Contains(body, `"c2"`) {
		t.Fatalf("first page: %d %s", code, body)
	}
	code, body = e.do("GET", "/api/v1/credentials?limit=2&cursor=c1", nil)
	if code != 200 || !strings.Contains(body, `"c2"`) || strings.Contains(body, `"c0"`) || strings.Contains(body, "page-pw-123") {
		t.Fatalf("second page: %d %s", code, body)
	}
}

// TestUpdateWithRefusedSecretSavesNothing: an edit that also carries a secret
// the vault would refuse changes nothing at all, rather than saving the new
// name and username unaudited while answering 400. A good edit is audited as
// an update and a rotation.
func TestUpdateWithRefusedSecretSavesNothing(t *testing.T) {
	e := newHandlerEnv(t)
	code, body := e.do("POST", "/api/v1/credentials/generate-ssh-key", map[string]any{"name": "key", "username": "deploy"})
	if code != 201 {
		t.Fatalf("generate: %d %s", code, body)
	}
	id := idOf(t, body)

	code, body = e.do("PATCH", "/api/v1/credentials/"+id, map[string]any{"name": "renamed", "username": "other", "private_key": "junk"})
	if code != 400 {
		t.Fatalf("update with a junk key: %d %s", code, body)
	}
	c, err := e.vault.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "key" || c.Username != "deploy" {
		t.Fatalf("a refused update saved its metadata: name %q username %q", c.Name, c.Username)
	}
	if n := auditCount(t, e.db, "credential.update") + auditCount(t, e.db, "credential.rotate"); n != 0 {
		t.Fatalf("a refused update wrote %d audit rows", n)
	}

	code, body = e.do("PATCH", "/api/v1/credentials/"+id, map[string]any{"name": "renamed", "username": "other", "password": "a new long passphrase"})
	if code != 400 {
		t.Fatalf("a password for an ssh_key credential must be refused: %d %s", code, body)
	}
	if c, _ := e.vault.Get(context.Background(), id); c.Name != "key" {
		t.Fatalf("a refused update renamed the credential to %q", c.Name)
	}

	code, body = e.do("PATCH", "/api/v1/credentials/"+id, map[string]any{"name": "renamed"})
	if code != 200 || auditCount(t, e.db, "credential.update") != 1 {
		t.Fatalf("a plain rename: %d %s", code, body)
	}
}
