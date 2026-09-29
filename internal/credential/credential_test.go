// SPDX-License-Identifier: Apache-2.0

package credential

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

func testVault(t *testing.T) (*Vault, *store.DB) {
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
	kek, _ := crypto.NewLocalKEK(bytes.Repeat([]byte{4}, 32))
	ring, err := keyring.Open(ctx, db, kek)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	return NewVault(db, ring), db
}

func TestPasswordRoundTrip(t *testing.T) {
	v, _ := testVault(t)
	ctx := context.Background()
	c := &Credential{Name: "prod-root", Type: TypePassword, Mode: ModeVaulted, Username: "root"}
	if err := v.Create(ctx, c, &Secret{Password: "s3cret-pw"}, ""); err != nil {
		t.Fatal(err)
	}
	if !c.HasSecret || c.KeyVersion != 1 || c.ID == "" {
		t.Fatalf("unexpected: %+v", c)
	}
	o, err := v.Open(ctx, c.ID)
	if err != nil || o.Password != "s3cret-pw" || o.PrivateKey != nil {
		t.Fatalf("open: %v %+v", err, o)
	}
	o.Close()
	if o.Password != "" {
		t.Fatal("close must clear")
	}
	if err := v.Create(ctx, &Credential{Name: "prod-root", Type: TypePassword, Mode: ModeVaulted, Username: "x"}, &Secret{Password: "p"}, ""); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected duplicate, got %v", err)
	}
	if err := v.Create(ctx, &Credential{Name: "nouser", Type: TypePassword, Mode: ModeVaulted}, &Secret{Password: "p"}, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected invalid, got %v", err)
	}
	if err := v.Create(ctx, &Credential{Name: "dom", Type: TypeDomain, Mode: ModeVaulted, Username: "svc"}, &Secret{Password: "p"}, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("domain without domain must fail, got %v", err)
	}
}

func TestSSHKeyDerivesPublicKey(t *testing.T) {
	v, _ := testVault(t)
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "")
	pemText := string(pem.EncodeToMemory(block))
	sshPub, _ := ssh.NewPublicKey(pub)
	want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	c := &Credential{Name: "deploy-key", Type: TypeSSHKey, Mode: ModeVaulted, Username: "deploy"}
	if err := v.Create(ctx, c, &Secret{PrivateKey: pemText}, ""); err != nil {
		t.Fatal(err)
	}
	if c.PublicKey != want {
		t.Fatalf("public key mismatch:\n%s\n%s", c.PublicKey, want)
	}
	o, err := v.Open(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ssh.ParsePrivateKey(o.PrivateKey); err != nil {
		t.Fatalf("stored key unparsable: %v", err)
	}
	o.Close()
	if err := v.Create(ctx, &Credential{Name: "junk", Type: TypeSSHKey, Mode: ModeVaulted, Username: "u"}, &Secret{PrivateKey: "not a key"}, ""); !errors.Is(err, ErrBadKey) {
		t.Fatalf("expected bad key, got %v", err)
	}

	// Rotate to a generated key: public key changes, rotated_at set.
	gen, err := GenerateSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	rot, err := v.Rotate(ctx, c.ID, &Secret{PrivateKey: gen})
	if err != nil {
		t.Fatal(err)
	}
	if rot.PublicKey == want || rot.RotatedAt == nil || !strings.HasPrefix(rot.PublicKey, "ssh-ed25519 ") {
		t.Fatalf("rotate: %+v", rot)
	}
	// CA needs no username.
	ca := &Credential{Name: "ca", Type: TypeSSHCA, Mode: ModeVaulted}
	if err := v.Create(ctx, ca, &Secret{PrivateKey: gen}, ""); err != nil || ca.PublicKey == "" {
		t.Fatalf("ca: %v", err)
	}
}

func TestEncryptedPEM(t *testing.T) {
	v, _ := testVault(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("open sesame"))
	if err != nil {
		t.Fatal(err)
	}
	pemText := string(pem.EncodeToMemory(block))
	mk := func(name, pass string) error {
		return v.Create(ctx, &Credential{Name: name, Type: TypeSSHKey, Mode: ModeVaulted, Username: "u"}, &Secret{PrivateKey: pemText, Passphrase: pass}, "")
	}
	if err := mk("nopass", ""); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("missing passphrase: %v", err)
	}
	if err := mk("wrongpass", "nope"); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if err := mk("rightpass", "open sesame"); err != nil {
		t.Fatalf("right passphrase: %v", err)
	}
	c, _, _ := v.List(ctx, "", 10)
	o, err := v.Open(ctx, c[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ssh.ParsePrivateKey(o.PrivateKey); err != nil {
		t.Fatalf("stored key must be decrypted: %v", err)
	}
}

func TestNoSecretModes(t *testing.T) {
	v, _ := testVault(t)
	ctx := context.Background()
	ic := &Credential{Name: "eic", Type: TypeEC2InstanceConnect, Mode: ModeVaulted, Username: "ec2-user"}
	if err := v.Create(ctx, ic, nil, ""); err != nil || ic.HasSecret {
		t.Fatalf("eic: %v %+v", err, ic)
	}
	if _, err := v.Open(ctx, ic.ID); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("expected no secret, got %v", err)
	}
	if err := v.Create(ctx, &Credential{Name: "eic2", Type: TypeEC2InstanceConnect, Mode: ModeUserSupplied, Username: "u"}, nil, ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("eic must be vaulted")
	}
	us := &Credential{Name: "ask", Type: TypePassword, Mode: ModeUserSupplied, Username: "ignored"}
	if err := v.Create(ctx, us, nil, ""); err != nil || us.HasSecret || us.Username != "" {
		t.Fatalf("user_supplied: %v %+v", err, us)
	}
	if err := v.Create(ctx, &Credential{Name: "ask2", Type: TypePassword, Mode: ModePassthrough}, &Secret{Password: "x"}, ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("passthrough must not carry a secret")
	}
	if _, err := v.Rotate(ctx, us.ID, &Secret{Password: "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatal("rotate on user_supplied must fail")
	}
}

func TestCiphertextBoundToRow(t *testing.T) {
	v, db := testVault(t)
	ctx := context.Background()
	a := &Credential{Name: "a", Type: TypePassword, Mode: ModeVaulted, Username: "a"}
	b := &Credential{Name: "b", Type: TypePassword, Mode: ModeVaulted, Username: "b"}
	if err := v.Create(ctx, a, &Secret{Password: "pa"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := v.Create(ctx, b, &Secret{Password: "pb"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, db.Rebind(`UPDATE credentials SET secret_enc = (SELECT secret_enc FROM credentials WHERE id = ?) WHERE id = ?`), a.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Open(ctx, b.ID); err == nil {
		t.Fatal("moved ciphertext must not open under another row")
	}
	if o, err := v.Open(ctx, a.ID); err != nil || o.Password != "pa" {
		t.Fatalf("original still opens: %v", err)
	}
}

func TestDeleteAndInUse(t *testing.T) {
	v, db := testVault(t)
	ctx := context.Background()
	c := &Credential{Name: "used", Type: TypePassword, Mode: ModeVaulted, Username: "u"}
	if err := v.Create(ctx, c, &Secret{Password: "p"}, ""); err != nil {
		t.Fatal(err)
	}
	now := store.TimeArg(store.NullTime{}.Time)
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t1', 'box', '10.0.0.1', 'linux', ?, ?)`), now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO target_credentials (target_id, protocol, credential_id) VALUES ('t1', 'ssh', ?)`), c.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := v.Get(ctx, c.ID)
	if got.InUseBy.Targets != 1 {
		t.Fatalf("expected in_use_by.targets=1, got %+v", got.InUseBy)
	}
	if err := v.Delete(ctx, c.ID); !errors.Is(err, ErrInUse) {
		t.Fatalf("expected in use, got %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM target_credentials`); err != nil {
		t.Fatal(err)
	}
	if err := v.Delete(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get(ctx, c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("expected not found after delete")
	}
}

// ---- handler tests

type env struct {
	srv    http.Handler
	cookie *http.Cookie
	csrf   string
}

func newHandlerEnv(t *testing.T) *env {
	t.Helper()
	v, db := testVault(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
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
	mux := http.NewServeMux()
	(&AdminHandler{Vault: v, Audit: audit.NewLog(db), Log: log}).Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	return &env{srv: mw.Authenticate(mw.CSRF(mux)), cookie: &http.Cookie{Name: auth.CookieName, Value: token}, csrf: sessions.CSRFToken(sess.ID)}
}

func (e *env) do(method, path string, body any) (int, string) {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrf)
	req.AddCookie(e.cookie)
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	return rr.Code, rr.Body.String()
}

func assertNoSecrets(t *testing.T, body string) {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("bad json: %s", body)
	}
	var walk func(any)
	walk = func(x any) {
		switch n := x.(type) {
		case map[string]any:
			for k, val := range n {
				if k == "password" || k == "private_key" || k == "private_key_passphrase" || k == "secret_enc" {
					t.Fatalf("secret field %q leaked in response: %s", k, body)
				}
				walk(val)
			}
		case []any:
			for _, val := range n {
				walk(val)
			}
		}
	}
	walk(v)
}

func TestHandlersNeverReturnSecrets(t *testing.T) {
	e := newHandlerEnv(t)
	code, body := e.do("POST", "/api/v1/credentials", map[string]any{"name": "pw", "type": "password", "mode": "vaulted", "username": "root", "password": "hunter2hunter2"})
	if code != 201 {
		t.Fatalf("create: %d %s", code, body)
	}
	assertNoSecrets(t, body)
	var created Credential
	_ = json.Unmarshal([]byte(body), &created)
	if !created.HasSecret {
		t.Fatal("has_secret should be true")
	}

	// Generated ssh key: only the public half comes back.
	code, body = e.do("POST", "/api/v1/credentials", map[string]any{"name": "gen", "type": "ssh_key", "mode": "vaulted", "username": "deploy"})
	if code != 201 || !strings.Contains(body, "ssh-ed25519 ") {
		t.Fatalf("generate via create: %d %s", code, body)
	}
	assertNoSecrets(t, body)
	code, body = e.do("POST", "/api/v1/credentials/generate-ssh-key", map[string]any{"name": "gen2", "username": "deploy"})
	if code != 201 || !strings.Contains(body, "ssh-ed25519 ") {
		t.Fatalf("generate endpoint: %d %s", code, body)
	}
	assertNoSecrets(t, body)

	code, body = e.do("GET", "/api/v1/credentials", nil)
	if code != 200 || !strings.Contains(body, `"items"`) {
		t.Fatalf("list: %d %s", code, body)
	}
	assertNoSecrets(t, body)
	code, body = e.do("GET", "/api/v1/credentials/"+created.ID, nil)
	if code != 200 {
		t.Fatalf("get: %d %s", code, body)
	}
	assertNoSecrets(t, body)

	code, body = e.do("PATCH", "/api/v1/credentials/"+created.ID, map[string]any{"name": "pw2", "password": "rotated-secret"})
	if code != 200 || !strings.Contains(body, `"rotated_at"`) || !strings.Contains(body, `"pw2"`) {
		t.Fatalf("update+rotate: %d %s", code, body)
	}
	assertNoSecrets(t, body)
	if code, body = e.do("PATCH", "/api/v1/credentials/"+created.ID, map[string]any{"type": "ssh_key"}); code != 400 {
		t.Fatalf("type change must be rejected: %d %s", code, body)
	}
	if code, _ = e.do("POST", "/api/v1/credentials/"+created.ID+"/rotate", map[string]any{"password": "again"}); code != 200 {
		t.Fatalf("rotate: %d", code)
	}
	if code, _ = e.do("DELETE", "/api/v1/credentials/"+created.ID, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ = e.do("GET", "/api/v1/credentials/"+created.ID, nil); code != 404 {
		t.Fatalf("expected 404 after delete, got %d", code)
	}
	if code, _ = e.do("POST", "/api/v1/credentials", map[string]any{"name": "bad", "type": "password", "mode": "vaulted"}); code != 400 {
		t.Fatalf("validation error should be 400, got %d", code)
	}
}

// TestCertificateAuthoritySettings: the lifetime and the principal allowlist
// of an ssh_ca credential round-trip, are validated, and are refused on
// every other type (ADR 0022).
func TestCertificateAuthoritySettings(t *testing.T) {
	ctx := context.Background()
	v, _ := testVault(t)
	caPEM, err := GenerateSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	c := &Credential{Name: "ca", Type: TypeSSHCA, Mode: ModeVaulted, CertificateTTLSeconds: 120, CertificatePrincipals: []string{" deploy ", "ops", "deploy", ""}}
	if err := v.Create(ctx, c, &Secret{PrivateKey: caPEM}, ""); err != nil {
		t.Fatal(err)
	}
	got, err := v.Get(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CertificateTTLSeconds != 120 || len(got.CertificatePrincipals) != 2 || got.CertificatePrincipals[0] != "deploy" || got.CertificatePrincipals[1] != "ops" {
		t.Fatalf("round trip: ttl=%d principals=%v", got.CertificateTTLSeconds, got.CertificatePrincipals)
	}
	if got.CertificateTTL() != 120*time.Second || !got.PermitsPrincipal("ops") || got.PermitsPrincipal("root") {
		t.Fatalf("helpers: ttl=%s ops=%v root=%v", got.CertificateTTL(), got.PermitsPrincipal("ops"), got.PermitsPrincipal("root"))
	}
	// Defaults: unset lifetime reads as the default, empty list permits anyone.
	if _, err := v.Update(ctx, c.ID, Metadata{Name: "ca"}); err != nil {
		t.Fatal(err)
	}
	got, _ = v.Get(ctx, c.ID)
	if got.CertificateTTLSeconds != 0 || got.CertificateTTL() != DefaultCertificateTTL*time.Second || len(got.CertificatePrincipals) != 0 || !got.PermitsPrincipal("anyone") {
		t.Fatalf("defaults: %+v", got)
	}
	for _, bad := range []Metadata{
		{Name: "ca", CertificateTTLSeconds: 30},
		{Name: "ca", CertificateTTLSeconds: 7200},
		{Name: "ca", CertificatePrincipals: []string{"has space"}},
		{Name: "ca", CertificatePrincipals: []string{strings.Repeat("x", 65)}},
	} {
		if _, err := v.Update(ctx, c.ID, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v must be refused, got %v", bad, err)
		}
	}
	pw := &Credential{Name: "pw", Type: TypePassword, Mode: ModeVaulted, Username: "root", CertificateTTLSeconds: 300}
	if err := v.Create(ctx, pw, &Secret{Password: "hunter2hunter2"}, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("certificate settings on a password credential must be refused, got %v", err)
	}
}

// TestCertificateAuthorityHandlerFields: the API creates a CA with a
// generated key and the settings, never returns the key, and an update can
// clear the fixed username so each user logs in as themselves.
func TestCertificateAuthorityHandlerFields(t *testing.T) {
	e := newHandlerEnv(t)
	code, body := e.do("POST", "/api/v1/credentials", map[string]any{"name": "ca", "type": "ssh_ca", "mode": "vaulted", "username": "deploy",
		"certificate_ttl_seconds": 600, "certificate_principals": []string{"deploy"}})
	if code != 201 || !strings.Contains(body, "ssh-ed25519 ") || !strings.Contains(body, `"certificate_ttl_seconds":600`) || !strings.Contains(body, `"certificate_principals":["deploy"]`) {
		t.Fatalf("create ca: %d %s", code, body)
	}
	assertNoSecrets(t, body)
	var created Credential
	_ = json.Unmarshal([]byte(body), &created)

	code, body = e.do("PATCH", "/api/v1/credentials/"+created.ID, map[string]any{"username": "", "certificate_principals": []string{}})
	if code != 200 || strings.Contains(body, `"username"`) || strings.Contains(body, `"certificate_principals"`) || !strings.Contains(body, `"certificate_ttl_seconds":600`) {
		t.Fatalf("clearing username and principals keeps the ttl: %d %s", code, body)
	}
	code, body = e.do("PATCH", "/api/v1/credentials/"+created.ID, map[string]any{"name": "ca-renamed"})
	if code != 200 || !strings.Contains(body, `"certificate_ttl_seconds":600`) {
		t.Fatalf("a body without the settings leaves them alone: %d %s", code, body)
	}
	code, body = e.do("PATCH", "/api/v1/credentials/"+created.ID, map[string]any{"certificate_ttl_seconds": 10})
	if code != 400 {
		t.Fatalf("ttl below the minimum: %d %s", code, body)
	}
}

// TestCertificateAuthorityRotation: prepare seals a next key beside the
// signing key under its own scope, cut over swaps and keeps the old public
// key as retired, cancel and retire clear their halves, and in-place rotate
// is refused for an authority (ADR 0022).
func TestCertificateAuthorityRotation(t *testing.T) {
	ctx := context.Background()
	v, db := testVault(t)
	first, _ := GenerateSSHKey()
	next, _ := GenerateSSHKey()
	c := &Credential{Name: "ca", Type: TypeSSHCA, Mode: ModeVaulted}
	if err := v.Create(ctx, c, &Secret{PrivateKey: first}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Rotate(ctx, c.ID, &Secret{PrivateKey: next}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("in-place rotate of an authority must be refused, got %v", err)
	}
	if _, err := v.CutOver(ctx, c.ID); !errors.Is(err, ErrNoRotation) {
		t.Fatalf("cut over without a prepared key: %v", err)
	}
	if _, err := v.PrepareRotation(ctx, c.ID, &Secret{PrivateKey: first}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("the next key must differ from the current one, got %v", err)
	}
	got, err := v.PrepareRotation(ctx, c.ID, &Secret{PrivateKey: next})
	if err != nil {
		t.Fatal(err)
	}
	if got.Rotation == nil || got.Rotation.PendingPublicKey == "" || got.Rotation.PendingSince == nil || got.Rotation.PendingPublicKey == got.PublicKey {
		t.Fatalf("prepared: %+v", got.Rotation)
	}
	if _, err := v.PrepareRotation(ctx, c.ID, &Secret{PrivateKey: next}); !errors.Is(err, ErrRotationPending) {
		t.Fatalf("second prepare must be refused, got %v", err)
	}
	// The signing key is untouched; the pending key opens separately and is
	// bound to its own column: moved into secret_enc it does not unseal.
	cur, err := v.Open(ctx, c.ID)
	if err != nil || cur.PublicKey != got.PublicKey {
		t.Fatalf("open current: %v", err)
	}
	cur.Close()
	pend, err := v.OpenPending(ctx, c.ID)
	if err != nil || pend.PublicKey != got.Rotation.PendingPublicKey {
		t.Fatalf("open pending: %v", err)
	}
	pend.Close()
	if _, err := db.ExecContext(ctx, db.Rebind(`UPDATE credentials SET secret_enc = pending_secret_enc, key_version = pending_key_version WHERE id = ?`), c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Open(ctx, c.ID); err == nil {
		t.Fatal("a pending ciphertext moved into the signing column must not unseal")
	}
	if _, err := v.CancelRotation(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ = v.Get(ctx, c.ID); got.Rotation != nil {
		t.Fatalf("cancel should clear the pending half: %+v", got.Rotation)
	}
	// Restore the signing key and run the full cycle.
	if _, err := db.ExecContext(ctx, db.Rebind(`DELETE FROM credentials WHERE id = ?`), c.ID); err != nil {
		t.Fatal(err)
	}
	c = &Credential{Name: "ca2", Type: TypeSSHCA, Mode: ModeVaulted}
	if err := v.Create(ctx, c, &Secret{PrivateKey: first}, ""); err != nil {
		t.Fatal(err)
	}
	oldPub := c.PublicKey
	if _, err := v.PrepareRotation(ctx, c.ID, &Secret{PrivateKey: next}); err != nil {
		t.Fatal(err)
	}
	got, err = v.CutOver(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicKey == oldPub || got.Rotation == nil || got.Rotation.PendingPublicKey != "" || got.Rotation.RetiredPublicKey != oldPub || got.RotatedAt == nil {
		t.Fatalf("cut over: pub=%q rotation=%+v rotated=%v", got.PublicKey[:20], got.Rotation, got.RotatedAt)
	}
	opened, err := v.Open(ctx, c.ID)
	if err != nil || opened.PublicKey != got.PublicKey {
		t.Fatalf("the new key signs after cut over: %v", err)
	}
	opened.Close()
	if _, err := v.OpenPending(ctx, c.ID); !errors.Is(err, ErrNoRotation) {
		t.Fatalf("nothing pending after cut over, got %v", err)
	}
	if got, err = v.Retire(ctx, c.ID); err != nil || got.Rotation != nil {
		t.Fatalf("retire: %v %+v", err, got.Rotation)
	}
	if _, err := v.Retire(ctx, c.ID); !errors.Is(err, ErrNoRotation) {
		t.Fatalf("second retire: %v", err)
	}
}

// TestCertificateAuthorityRotationRoutes: the rotate route prepares (and
// generates) for an authority, an update body with a key is refused, and
// the cut-over, cancel and retire routes drive the state; keys never leak.
func TestCertificateAuthorityRotationRoutes(t *testing.T) {
	e := newHandlerEnv(t)
	code, body := e.do("POST", "/api/v1/credentials", map[string]any{"name": "ca", "type": "ssh_ca", "mode": "vaulted"})
	if code != 201 {
		t.Fatalf("create: %d %s", code, body)
	}
	var c Credential
	_ = json.Unmarshal([]byte(body), &c)
	code, body = e.do("PATCH", "/api/v1/credentials/"+c.ID, map[string]any{"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"})
	if code != 400 {
		t.Fatalf("a key in an update body must be refused for an authority: %d %s", code, body)
	}
	code, body = e.do("POST", "/api/v1/credentials/"+c.ID+"/rotate", map[string]any{})
	if code != 200 || !strings.Contains(body, `"pending_public_key":"ssh-ed25519 `) || !strings.Contains(body, `"pending_since"`) {
		t.Fatalf("prepare with a generated key: %d %s", code, body)
	}
	assertNoSecrets(t, body)
	if code, body = e.do("POST", "/api/v1/credentials/"+c.ID+"/rotate", map[string]any{}); code != 409 || !strings.Contains(body, "rotation_pending") {
		t.Fatalf("second prepare: %d %s", code, body)
	}
	if code, body = e.do("DELETE", "/api/v1/credentials/"+c.ID+"/rotate", nil); code != 200 || strings.Contains(body, "pending_public_key") {
		t.Fatalf("cancel: %d %s", code, body)
	}
	if code, body = e.do("POST", "/api/v1/credentials/"+c.ID+"/rotate/cut-over", nil); code != 409 || !strings.Contains(body, "no_rotation") {
		t.Fatalf("cut over with nothing prepared: %d %s", code, body)
	}
	if code, body = e.do("POST", "/api/v1/credentials/"+c.ID+"/rotate", map[string]any{}); code != 200 {
		t.Fatalf("prepare again: %d %s", code, body)
	}
	code, body = e.do("POST", "/api/v1/credentials/"+c.ID+"/rotate/cut-over", nil)
	if code != 200 || strings.Contains(body, "pending_public_key") || !strings.Contains(body, `"retired_public_key":"`+c.PublicKey+`"`) || !strings.Contains(body, `"rotated_at"`) {
		t.Fatalf("cut over: %d %s", code, body)
	}
	assertNoSecrets(t, body)
	if code, body = e.do("POST", "/api/v1/credentials/"+c.ID+"/rotate/retire", nil); code != 200 || strings.Contains(body, "retired_public_key") {
		t.Fatalf("retire: %d %s", code, body)
	}
	if code, body = e.do("POST", "/api/v1/credentials/"+c.ID+"/rotate/retire", nil); code != 409 {
		t.Fatalf("retire twice: %d %s", code, body)
	}
}
