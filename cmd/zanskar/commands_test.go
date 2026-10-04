// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// cliGateway is an installed gateway as the commands see it: a SQLite file,
// a master key and a recordings directory, configured through the same
// environment variables the service reads.
type cliGateway struct {
	dir, dbPath, recDir string
	key                 []byte
	keyB64              string
}

// vaultTestSecret is a made-up credential password the backup test seals in
// the vault, then looks for in the archive in the clear.
const vaultTestSecret = "s3cret-pw-in-vault" // gitleaks:allow -- test fixture, not a real secret

func newCLIGateway(t *testing.T, migrate bool) *cliGateway {
	t.Helper()
	g := &cliGateway{dir: t.TempDir(), key: make([]byte, 32)}
	if _, err := rand.Read(g.key); err != nil {
		t.Fatal(err)
	}
	g.keyB64 = base64.StdEncoding.EncodeToString(g.key)
	g.dbPath = filepath.Join(g.dir, "data", "zanskar.db")
	g.recDir = filepath.Join(g.dir, "data", "recordings")
	if err := os.MkdirAll(filepath.Dir(g.dbPath), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZANSKAR_DB_DRIVER", "sqlite")
	t.Setenv("ZANSKAR_DB_DSN", "file:"+g.dbPath+"?_pragma=foreign_keys(1)")
	t.Setenv("ZANSKAR_MASTER_KEY", g.keyB64)
	t.Setenv("ZANSKAR_MASTER_KEY_FILE", "")
	t.Setenv("ZANSKAR_RECORDINGS_DIR", g.recDir)
	t.Setenv("ZANSKAR_RECORDINGS_S3_BUCKET", "")
	t.Setenv("ZANSKAR_ADMIN_PASSWORD", "")
	if migrate {
		g.with(t, func(ctx context.Context, db *store.DB, _ *keyring.Ring) {
			if _, err := store.Migrate(ctx, db); err != nil {
				t.Fatal(err)
			}
		})
	}
	return g
}

// with opens the gateway's database (and, after migration, its key ring)
// for setup or inspection, and closes both before the next command runs.
func (g *cliGateway) with(t *testing.T, fn func(context.Context, *store.DB, *keyring.Ring)) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, "sqlite", "file:"+g.dbPath+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var ring *keyring.Ring
	if pending, _ := store.Pending(ctx, db); len(pending) == 0 {
		kek, _ := crypto.NewLocalKEK(g.key)
		if ring, err = keyring.Open(ctx, db, kek); err != nil {
			t.Fatal(err)
		}
		defer ring.Close()
	}
	fn(ctx, db, ring)
}

// output runs fn with stdout and stderr captured.
func output(t *testing.T, fn func() error) (stdout, stderr string, err error) {
	t.Helper()
	capture := func(dst **os.File) (func() string, error) {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		saved := *dst
		*dst = w
		done := make(chan string)
		go func() { b, _ := io.ReadAll(r); done <- string(b) }()
		return func() string { _ = w.Close(); *dst = saved; return <-done }, nil
	}
	outDone, e1 := capture(&os.Stdout)
	errDone, e2 := capture(&os.Stderr)
	if e1 != nil || e2 != nil {
		t.Fatal(e1, e2)
	}
	err = fn()
	return outDone(), errDone(), err
}

func lastAudit(t *testing.T, g *cliGateway, action string) audit.Event {
	t.Helper()
	var ev audit.Event
	g.with(t, func(ctx context.Context, db *store.DB, _ *keyring.Ring) {
		evs, _, err := audit.NewLog(db).List(ctx, audit.Filter{Action: action, Limit: 1})
		if err != nil || len(evs) == 0 {
			t.Fatalf("no %s event: %v", action, err)
		}
		ev = evs[0]
	})
	return ev
}

// TestBackupAndRestore: a backup holds the database and the recordings but
// never the master key or a secret in the clear; restoring it brings back
// users, readable credentials and recordings; an existing database is only
// overwritten with --force; and a backup made under another key says so.
func TestBackupAndRestore(t *testing.T) {
	g := newCLIGateway(t, true)
	var credID string
	g.with(t, func(ctx context.Context, db *store.DB, ring *keyring.Ring) {
		u := &user.User{Username: "alice", DisplayName: "Alice", Roles: []user.Role{user.RoleUser}}
		if err := user.NewRepo(db).Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		c := &credential.Credential{Name: "svc", Type: credential.TypePassword, Mode: credential.ModeVaulted, Username: "svc"}
		if err := credential.NewVault(db, ring).Create(ctx, c, &credential.Secret{Password: vaultTestSecret}, u.ID); err != nil {
			t.Fatal(err)
		}
		credID = c.ID
	})
	if err := os.MkdirAll(g.recDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(g.recDir, "s1.cast"), []byte("recorded session"), 0o600); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(g.dir, "backup.tar.gz")
	if out, _, err := output(t, func() error { return runBackup([]string{"-out", archive}) }); err != nil || !strings.Contains(out, "NOT in this archive") {
		t.Fatalf("backup: %v\n%s", err, out)
	}

	t.Run("archive holds no key and no secret in the clear", func(t *testing.T) {
		files := readTarGz(t, archive)
		for _, name := range []string{"manifest.json", "db/zanskar.db", "recordings/s1.cast"} {
			if _, ok := files[name]; !ok {
				t.Fatalf("archive lacks %s (has %v)", name, keys(files))
			}
		}
		for name, body := range files {
			for _, secret := range [][]byte{[]byte(g.keyB64), g.key, []byte(vaultTestSecret)} {
				if bytes.Contains(body, secret) {
					t.Fatalf("%s carries a secret in the clear", name)
				}
			}
		}
		var man backupManifest
		_ = json.Unmarshal(files["manifest.json"], &man)
		if man.KeyFingerprint != keyFingerprint(g.key) || !man.RecordingsIncluded || man.RecordingsBackend != "local" || man.DBDriver != "sqlite" {
			t.Fatalf("manifest %+v", man)
		}
	})

	t.Run("an existing database needs --force", func(t *testing.T) {
		_, _, err := output(t, func() error { return runRestore([]string{"-in", archive}) })
		if err == nil || !strings.Contains(err.Error(), "--force") {
			t.Fatalf("got %v, want a refusal naming --force", err)
		}
	})

	t.Run("restore brings everything back", func(t *testing.T) {
		for _, p := range []string{g.dbPath, g.dbPath + "-wal", g.dbPath + "-shm"} {
			_ = os.Remove(p)
		}
		if err := os.RemoveAll(g.recDir); err != nil {
			t.Fatal(err)
		}
		out, stderr, err := output(t, func() error { return runRestore([]string{"-in", archive}) })
		if err != nil || strings.Contains(stderr, "DIFFERENT master key") {
			t.Fatalf("restore: %v\n%s%s", err, out, stderr)
		}
		g.with(t, func(ctx context.Context, db *store.DB, ring *keyring.Ring) {
			if _, err := user.NewRepo(db).GetByUsername(ctx, "alice"); err != nil {
				t.Fatalf("alice after restore: %v", err)
			}
			opened, err := credential.NewVault(db, ring).Open(ctx, credID)
			if err != nil || opened.Password != vaultTestSecret {
				t.Fatalf("credential after restore: %v", err)
			}
			opened.Close()
		})
		if b, err := os.ReadFile(filepath.Join(g.recDir, "s1.cast")); err != nil || string(b) != "recorded session" {
			t.Fatalf("recording after restore: %q %v", b, err)
		}
		if info, err := os.Stat(g.dbPath); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("restored database mode: %v %v", info, err)
		}
	})

	t.Run("a backup from another key warns", func(t *testing.T) {
		other := make([]byte, 32)
		_, _ = rand.Read(other)
		t.Setenv("ZANSKAR_MASTER_KEY", base64.StdEncoding.EncodeToString(other))
		_, stderr, err := output(t, func() error { return runRestore([]string{"-in", archive, "-force"}) })
		if err != nil || !strings.Contains(stderr, "DIFFERENT master key") {
			t.Fatalf("got %v, stderr %q; want the different-key warning", err, stderr)
		}
	})

	t.Run("refusals", func(t *testing.T) {
		if _, _, err := output(t, func() error { return runRestore(nil) }); err == nil || !strings.Contains(err.Error(), "--in") {
			t.Fatalf("restore without --in: %v", err)
		}
		t.Setenv("ZANSKAR_DB_DRIVER", "postgres")
		t.Setenv("ZANSKAR_DB_DSN", "postgres://zanskar@localhost/zanskar")
		if _, _, err := output(t, func() error { return runBackup([]string{"-out", archive}) }); err == nil || !strings.Contains(err.Error(), "pg_dump") {
			t.Fatalf("backup of PostgreSQL: %v", err)
		}
	})
}

func readTarGz(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- test archive
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	files := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return files
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			b, _ := io.ReadAll(tr)
			files[filepath.ToSlash(h.Name)] = b
		}
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestAuditVerifyAndReseal: verify passes an intact chain and fails a
// tampered one; reseal refuses without --yes and changes nothing, and with
// --yes repairs the chain and records that it did.
func TestAuditVerifyAndReseal(t *testing.T) {
	g := newCLIGateway(t, true)
	g.with(t, func(ctx context.Context, db *store.DB, _ *keyring.Ring) {
		log := audit.NewLog(db)
		for _, a := range []string{"user.login", "target.create", "user.logout"} {
			if _, err := log.Record(ctx, audit.Actor{IP: "203.0.113.1"}.Event(a, "user", "u1", audit.Success, map[string]any{"n": a})); err != nil {
				t.Fatal(err)
			}
		}
	})
	if out, _, err := output(t, runAuditVerify); err != nil || !strings.Contains(out, "intact: 3 event(s)") {
		t.Fatalf("verify an intact chain: %v %q", err, out)
	}
	if out, _, err := output(t, func() error { return runAuditReseal([]string{"--yes"}) }); err != nil || !strings.Contains(out, "already intact") {
		t.Fatalf("reseal an intact chain: %v %q", err, out)
	}

	g.with(t, func(ctx context.Context, db *store.DB, _ *keyring.Ring) {
		if _, err := db.ExecContext(ctx, db.Rebind(`UPDATE audit_events SET details = ? WHERE action = ?`), `{"n":"edited"}`, "target.create"); err != nil {
			t.Fatal(err)
		}
	})
	if _, stderr, err := output(t, runAuditVerify); err == nil || !strings.Contains(stderr, "BROKEN") {
		t.Fatalf("verify a tampered chain: %v %q", err, stderr)
	}
	if _, stderr, err := output(t, func() error { return runAuditReseal(nil) }); err == nil || !strings.Contains(stderr, "--yes") {
		t.Fatalf("reseal without --yes: %v %q", err, stderr)
	}
	if _, _, err := output(t, runAuditVerify); err == nil {
		t.Fatal("a refused reseal must leave the chain broken")
	}
	if out, _, err := output(t, func() error { return runAuditReseal([]string{"--yes"}) }); err != nil || !strings.Contains(out, "resealed") {
		t.Fatalf("reseal --yes: %v %q", err, out)
	}
	if out, _, err := output(t, runAuditVerify); err != nil || !strings.Contains(out, "intact") {
		t.Fatalf("verify after reseal: %v %q", err, out)
	}
	ev := lastAudit(t, g, "audit.reseal")
	var d map[string]any
	_ = json.Unmarshal(ev.Details, &d)
	if d["rows_rewritten"] == nil || d["reason"] == nil {
		t.Fatalf("audit.reseal details %v", d)
	}
}

// TestKeyStatusAndRotate: status reports the active data key and what each
// version seals; rotate starts a new version for new secrets, is audited, and
// leaves secrets sealed under the old version readable.
func TestKeyStatusAndRotate(t *testing.T) {
	g := newCLIGateway(t, true)
	var credID string
	g.with(t, func(ctx context.Context, db *store.DB, ring *keyring.Ring) {
		c := &credential.Credential{Name: "svc", Type: credential.TypePassword, Mode: credential.ModeVaulted, Username: "svc"}
		if err := credential.NewVault(db, ring).Create(ctx, c, &credential.Secret{Password: "before-rotation"}, ""); err != nil {
			t.Fatal(err)
		}
		credID = c.ID
	})
	out, _, err := output(t, runKeyStatus)
	if err != nil || !strings.Contains(out, "active data-key version: 1") || !strings.Contains(out, "v1: 1") {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if out, _, err := output(t, runKeyRotate); err != nil || !strings.Contains(out, "version 2 is now active") {
		t.Fatalf("rotate: %v\n%s", err, out)
	}
	if ev := lastAudit(t, g, "key.rotate"); ev.ObjectID != "2" {
		t.Fatalf("key.rotate names version %s, want 2", ev.ObjectID)
	}
	g.with(t, func(ctx context.Context, db *store.DB, ring *keyring.Ring) {
		if ring.ActiveVersion() != 2 {
			t.Fatalf("active version %d after rotate, want 2", ring.ActiveVersion())
		}
		opened, err := credential.NewVault(db, ring).Open(ctx, credID)
		if err != nil || opened.Password != "before-rotation" {
			t.Fatalf("a secret sealed under version 1: %v", err)
		}
		opened.Close()
	})
	for _, args := range [][]string{nil, {"spin"}} {
		if err := runKey(args); err == nil {
			t.Errorf("key %v: want a usage error", args)
		}
	}
	t.Setenv("ZANSKAR_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if _, _, err := output(t, runKeyStatus); err == nil {
		t.Fatal("status under the wrong master key must fail, not print")
	}
}

// TestAdminCommands: admin create makes an admin from the host (audited, the
// password never in the log), refuses a weak password, a duplicate and an
// unmigrated database; reset-mfa removes the authenticator and signs the
// user out everywhere, audited.
func TestAdminCommands(t *testing.T) {
	const pw = "a long enough passphrase 42"

	t.Run("refuses an unmigrated database", func(t *testing.T) {
		newCLIGateway(t, false)
		t.Setenv("ZANSKAR_ADMIN_PASSWORD", pw)
		err := runAdminCreate([]string{"-username", "root", "-name", "Root"})
		if err == nil || !strings.Contains(err.Error(), "migrate") {
			t.Fatalf("got %v, want a pending-migrations refusal", err)
		}
	})

	g := newCLIGateway(t, true)
	for _, c := range []struct {
		name string
		args []string
		pw   string
	}{
		{"usage", nil, pw},
		{"unknown subcommand", []string{"promote"}, pw},
		{"missing --name", []string{"create", "-username", "root"}, pw},
		{"weak password", []string{"create", "-username", "root", "-name", "Root"}, "short"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("ZANSKAR_ADMIN_PASSWORD", c.pw)
			if err := runAdmin(c.args); err == nil {
				t.Fatal("want an error")
			}
		})
	}

	t.Setenv("ZANSKAR_ADMIN_PASSWORD", pw)
	if out, _, err := output(t, func() error { return runAdmin([]string{"create", "-username", "root", "-name", "Root"}) }); err != nil || !strings.Contains(out, `created admin "root"`) {
		t.Fatalf("admin create: %v %q", err, out)
	}
	ev := lastAudit(t, g, "user.create")
	if bytes.Contains(ev.Details, []byte(pw)) || !bytes.Contains(ev.Details, []byte("zanskar admin create")) {
		t.Fatalf("user.create details %s", ev.Details)
	}
	if _, _, err := output(t, func() error { return runAdmin([]string{"create", "-username", "root", "-name", "Again"}) }); err == nil {
		t.Fatal("a duplicate username must be refused")
	}

	var rootID string
	g.with(t, func(ctx context.Context, db *store.DB, ring *keyring.Ring) {
		u, err := user.NewRepo(db).GetByUsername(ctx, "root")
		if err != nil || !u.HasRole(user.RoleAdmin) {
			t.Fatalf("root: %v %+v", err, u)
		}
		rootID = u.ID
		tp := auth.NewTOTP(db, ring, "Zanskar")
		enr, err := tp.Enroll(ctx, u.ID, u.Username)
		if err != nil {
			t.Fatal(err)
		}
		code, _ := totp.GenerateCode(enr.Secret, time.Now())
		if _, err := tp.Confirm(ctx, u.ID, code); err != nil {
			t.Fatal(err)
		}
		if _, _, err := auth.NewSessions(db, bytes.Repeat([]byte{1}, 32), false).Create(ctx, u.ID, "203.0.113.1", "test", true); err != nil {
			t.Fatal(err)
		}
	})

	if err := runAdmin([]string{"reset-mfa"}); err == nil {
		t.Fatal("reset-mfa without --username must be refused")
	}
	out, _, err := output(t, func() error { return runAdmin([]string{"reset-mfa", "-username", "root"}) })
	if err != nil || !strings.Contains(out, "1 session(s) revoked") {
		t.Fatalf("reset-mfa: %v %q", err, out)
	}
	g.with(t, func(ctx context.Context, db *store.DB, ring *keyring.Ring) {
		if on, err := auth.NewTOTP(db, ring, "Zanskar").Enrolled(ctx, rootID); err != nil || on {
			t.Fatalf("authenticator still enrolled after reset: %v %v", on, err)
		}
	})
	if ev := lastAudit(t, g, "user.mfa.reset"); ev.ObjectID != rootID {
		t.Fatalf("user.mfa.reset names %s, want %s", ev.ObjectID, rootID)
	}
}

// TestInitNonInteractive runs `zanskar init` as an installer script does. A
// first run writes a private env file with a new master key; a second run
// refuses without --force, and with --force rewrites the settings but keeps
// the master key (ADR 0014: a new key would make every stored credential
// unreadable). --print writes nothing, and behind-proxy mode marks cookies
// Secure through the proxy.
func TestInitNonInteractive(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "env")
	data := filepath.Join(dir, "lib")
	run := func(args ...string) (string, string, error) {
		return output(t, func() error {
			return runInit(append([]string{"-out", env, "-non-interactive", "-data-dir", data}, args...))
		})
	}
	read := func() string {
		b, err := os.ReadFile(env) // #nosec G304 -- test temp file
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	out, _, err := run("-tls-hosts", "zanskar.example.com,203.0.113.9", "-guacd", "127.0.0.1:4822")
	if err != nil || !strings.Contains(out, "A new master key was generated") {
		t.Fatalf("first init: %v\n%s", err, out)
	}
	first := read()
	key := masterKeyFrom(env)
	if raw, err := base64.StdEncoding.DecodeString(key); err != nil || len(raw) != 32 {
		t.Fatalf("master key %q is not 32 bytes of base64", key)
	}
	for _, want := range []string{"ZANSKAR_TLS_MODE=managed", "ZANSKAR_TLS_HOSTS=zanskar.example.com,203.0.113.9", "ZANSKAR_GUACD_ADDR=127.0.0.1:4822", data} {
		if !strings.Contains(first, want) {
			t.Errorf("env file lacks %q:\n%s", want, first)
		}
	}
	if info, err := os.Stat(env); err != nil || info.Mode().Perm()&0o007 != 0 {
		t.Fatalf("env file must not be readable by others: %v %v", info.Mode(), err)
	}

	if _, _, err := run(); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("second init without --force: %v", err)
	}
	if read() != first {
		t.Fatal("a refused init must leave the file alone")
	}

	printed, _, err := run("-print", "-guacd", "127.0.0.1:5000")
	if err != nil || !strings.Contains(printed, "ZANSKAR_MASTER_KEY="+key) || !strings.Contains(printed, "127.0.0.1:5000") {
		t.Fatalf("init --print: %v\n%s", err, printed)
	}
	if read() != first {
		t.Fatal("--print must not write the file")
	}

	out, _, err = run("-force", "-behind-proxy", "-redirect", "off")
	if err != nil {
		t.Fatalf("init --force: %v", err)
	}
	if masterKeyFrom(env) != key {
		t.Fatal("init --force replaced the master key")
	}
	if strings.Contains(out, "A new master key was generated") {
		t.Fatal("a kept key must not be announced as new")
	}
	after := read()
	// Proxy mode is implied by a loopback listener without a certificate;
	// what matters is that cookies stay Secure and the proxy is trusted.
	for _, want := range []string{"ZANSKAR_LISTEN_ADDR=127.0.0.1:8443", "ZANSKAR_TRUST_PROXY_TLS=true", "ZANSKAR_TRUSTED_PROXIES=127.0.0.1/32,::1/128"} {
		if !strings.Contains(after, want) {
			t.Errorf("behind-proxy env lacks %q:\n%s", want, after)
		}
	}
	if strings.Contains(after, "ZANSKAR_TLS_MODE=managed") {
		t.Error("behind-proxy env must not keep managed TLS")
	}

	if _, _, err := run("-force", "-tls-cert", "/nowhere/cert.pem"); err == nil {
		t.Fatal("a certificate without its key must be refused")
	}
	if _, _, err := run("-no-such-flag"); err == nil {
		t.Fatal("an unknown flag must be refused")
	}
}
