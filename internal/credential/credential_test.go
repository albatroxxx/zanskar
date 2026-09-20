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
