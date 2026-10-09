// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
)

// ringOpensWith reports whether key unwraps the gateway's key ring.
func ringOpensWith(t *testing.T, g *cliGateway, key []byte) bool {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, "sqlite", "file:"+g.dbPath+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	kek, err := crypto.NewLocalKEK(key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := keyring.Open(ctx, db, kek)
	if err != nil {
		return false
	}
	r.Close()
	return true
}

// sealCredential stores a vaulted password so a rotation has a secret to keep readable.
func sealCredential(t *testing.T, g *cliGateway, pw string) string {
	t.Helper()
	var id string
	g.with(t, func(ctx context.Context, db *store.DB, ring *keyring.Ring) {
		c := &credential.Credential{Name: "svc", Type: credential.TypePassword, Mode: credential.ModeVaulted, Username: "svc"}
		if err := credential.NewVault(db, ring).Create(ctx, c, &credential.Secret{Password: pw}, ""); err != nil {
			t.Fatal(err)
		}
		id = c.ID
	})
	return id
}

func randomKeyB64(t *testing.T) (string, []byte) {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k), k
}

// TestKeyDispatch: `zanskar key status` and `zanskar key rotate` reach their
// commands through the dispatcher, and rotate-master passes its flags on.
func TestKeyDispatch(t *testing.T) {
	newCLIGateway(t, true)
	if out, _, err := output(t, func() error { return runKey([]string{"status"}) }); err != nil || !strings.Contains(out, "active data-key version: 1") {
		t.Fatalf("key status: %v\n%s", err, out)
	}
	if out, _, err := output(t, func() error { return runKey([]string{"rotate"}) }); err != nil || !strings.Contains(out, "version 2 is now active") {
		t.Fatalf("key rotate: %v\n%s", err, out)
	}
	if _, _, err := output(t, func() error { return runKey([]string{"rotate-master", "-no-such-flag"}) }); err == nil {
		t.Fatal("rotate-master with an unknown flag must fail")
	}
}

// TestKeyStatusShowsRotatedAndRetired: after a master-key rewrap and a data
// key being retired, status shows when each happened instead of a dash, and
// counts sealed rows per version for every sealed table.
func TestKeyStatusShowsRotatedAndRetired(t *testing.T) {
	g := newCLIGateway(t, true)
	sealCredential(t, g, "pw-v1")
	if _, _, err := output(t, runKeyRotate); err != nil {
		t.Fatal(err)
	}
	newB64, newKey := randomKeyB64(t)
	t.Setenv("ZANSKAR_NEW_MASTER_KEY", newB64)
	if _, _, err := output(t, func() error { return runKeyRotateMaster([]string{"-yes"}) }); err != nil {
		t.Fatal(err)
	}
	g.key, g.keyB64 = newKey, newB64
	t.Setenv("ZANSKAR_MASTER_KEY", newB64)
	retired := time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)
	g.with(t, func(ctx context.Context, db *store.DB, _ *keyring.Ring) {
		if _, err := db.ExecContext(ctx, db.Rebind(`UPDATE key_versions SET retired_at = ? WHERE id = 1`), store.TimeArg(retired)); err != nil {
			t.Fatal(err)
		}
	})

	out, _, err := output(t, runKeyStatus)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out, "active data-key version: 2") {
		t.Fatalf("status must show version 2 active:\n%s", out)
	}
	today := time.Now().UTC().Format("2006-01-02")
	var v1, v2 string
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "1 "):
			v1 = line
		case strings.HasPrefix(line, "2 "):
			v2 = line
		}
	}
	// Columns: version, wrapped-by, created (one field), rotated (date time), retired (date time or -).
	f1, f2 := strings.Fields(v1), strings.Fields(v2)
	if len(f1) != 7 || f1[3] != today || f1[5]+" "+f1[6] != "2026-01-02 03:04" {
		t.Fatalf("version 1 must show its rewrap today and its retirement time: %q", v1)
	}
	if len(f2) != 6 || f2[3] != today || f2[5] != "-" {
		t.Fatalf("version 2 must show today's rewrap and a dash for retired: %q", v2)
	}
	for _, table := range []string{"credentials", "identity_providers", "mfa_totp"} {
		if !regexp.MustCompile(`(?m)^\s+` + table + `\s+`).MatchString(out) {
			t.Fatalf("status must list %s:\n%s", table, out)
		}
	}
	if !regexp.MustCompile(`(?m)^\s+credentials\s+v1: 1$`).MatchString(out) || !regexp.MustCompile(`(?m)^\s+mfa_totp\s+none$`).MatchString(out) {
		t.Fatalf("sealed-row counts:\n%s", out)
	}
	if strings.Contains(out, newB64) {
		t.Fatal("status must never print the master key")
	}
}

// TestKeyCommandsRefuseBadConfig: without a master key, or with a key file
// that others can read, the key commands refuse before touching anything.
func TestKeyCommandsRefuseBadConfig(t *testing.T) {
	g := newCLIGateway(t, true)
	t.Setenv("ZANSKAR_MASTER_KEY", "")
	for name, fn := range map[string]func() error{
		"status":        runKeyStatus,
		"rotate":        runKeyRotate,
		"rotate-master": func() error { return runKeyRotateMaster([]string{"-generate", "-yes"}) },
	} {
		if _, _, err := output(t, fn); err == nil || !strings.Contains(err.Error(), "ZANSKAR_MASTER_KEY") {
			t.Errorf("%s without a master key: %v", name, err)
		}
	}

	keyPath := filepath.Join(g.dir, "master.key")
	if err := os.WriteFile(keyPath, []byte(g.keyB64+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The package umask (0077) would strip the group bit from WriteFile's mode.
	if err := os.Chmod(keyPath, 0o640); err != nil { // #nosec G302 -- deliberately unsafe mode under test
		t.Fatal(err)
	}
	t.Setenv("ZANSKAR_MASTER_KEY_FILE", keyPath)
	if _, _, err := output(t, runKeyRotate); err == nil || !strings.Contains(err.Error(), "only its owner may read it") {
		t.Fatalf("a group-readable key file must be refused: %v", err)
	}
	if !ringOpensWith(t, g, g.key) {
		t.Fatal("nothing may change after a refusal")
	}
	g.with(t, func(ctx context.Context, db *store.DB, ring *keyring.Ring) {
		if ring.ActiveVersion() != 1 {
			t.Fatalf("a refused rotate must not start a new version (active %d)", ring.ActiveVersion())
		}
	})
}

// TestRotateMasterEnvFile: with -env-file the key line is replaced in place
// (other lines and the mode kept) and the new key is never printed; every
// unsafe input is refused before the rewrap, leaving the old key in force.
func TestRotateMasterEnvFile(t *testing.T) {
	g := newCLIGateway(t, true)
	credID := sealCredential(t, g, "survives-rewrap")
	t.Setenv("ZANSKAR_NEW_MASTER_KEY", "")
	envPath := filepath.Join(g.dir, "env")
	envBody := "# zanskar\nZANSKAR_LISTEN_ADDR=127.0.0.1:8443\nZANSKAR_MASTER_KEY=" + g.keyB64 + "\nZANSKAR_GUACD_ADDR=127.0.0.1:4822\n"
	if err := os.WriteFile(envPath, []byte(envBody), 0o600); err != nil {
		t.Fatal(err)
	}
	otherB64, _ := randomKeyB64(t)

	write := func(name, body string) string {
		p := filepath.Join(g.dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	refusals := []struct {
		name string
		args []string
		env  string // ZANSKAR_NEW_MASTER_KEY
		want string
	}{
		{"no -yes", []string{"-env-file", envPath, "-generate"}, "", "without -yes"},
		{"env file with another key", []string{"-env-file", write("env-other", "ZANSKAR_MASTER_KEY="+otherB64+"\n"), "-generate", "-yes"}, "", "different master key"},
		{"env file without the key line", []string{"-env-file", write("env-none", "ZANSKAR_LISTEN_ADDR=x\n"), "-generate", "-yes"}, "", "no ZANSKAR_MASTER_KEY line"},
		{"env file that does not exist", []string{"-env-file", filepath.Join(g.dir, "missing"), "-generate", "-yes"}, "", "cannot read the env file"},
		{"both files", []string{"-env-file", envPath, "-key-file", write("k", g.keyB64), "-generate", "-yes"}, "", "not both"},
		{"key file with another key", []string{"-key-file", write("k-other", otherB64+"\n"), "-generate", "-yes"}, "", "different master key"},
		{"key file that does not exist", []string{"-key-file", filepath.Join(g.dir, "nope.key"), "-generate", "-yes"}, "", "no such file"},
		{"short new key", []string{"-env-file", envPath, "-yes"}, base64.StdEncoding.EncodeToString([]byte("too short")), "32 bytes"},
		{"new key not base64", []string{"-env-file", envPath, "-yes"}, "!!not-base64!!", "32 bytes"},
	}
	for _, c := range refusals {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("ZANSKAR_NEW_MASTER_KEY", c.env)
			out, stderr, err := output(t, func() error { return runKeyRotateMaster(c.args) })
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want a refusal mentioning %q, got %v", c.want, err)
			}
			if strings.Contains(out, "rewrapped") {
				t.Fatalf("a refusal must not rewrap: %s", out)
			}
			if c.name == "no -yes" && !strings.Contains(stderr, "Re-run with -yes") {
				t.Fatalf("the refusal must say how to proceed: %q", stderr)
			}
			if !ringOpensWith(t, g, g.key) {
				t.Fatal("the old key must still open the ring")
			}
			if b, _ := os.ReadFile(envPath); string(b) != envBody { // #nosec G304 -- test temp file
				t.Fatalf("the env file must be untouched:\n%s", b)
			}
		})
	}

	out, stderr, err := output(t, func() error { return runKeyRotateMaster([]string{"-env-file", envPath, "-generate", "-yes"}) })
	if err != nil {
		t.Fatalf("rotate-master: %v\n%s", err, stderr)
	}
	if !strings.Contains(out, "rewrapped 1 data-key version(s)") || !strings.Contains(out, "updated ZANSKAR_MASTER_KEY in "+envPath) {
		t.Fatalf("output:\n%s", out)
	}
	newB64 := masterKeyFrom(envPath)
	newKey, err := base64.StdEncoding.DecodeString(newB64)
	if err != nil || len(newKey) != 32 || newB64 == g.keyB64 {
		t.Fatalf("env file must hold a new 32-byte key: %q %v", newB64, err)
	}
	if strings.Contains(out, newB64) || strings.Contains(stderr, newB64) {
		t.Fatal("a key written to the env file must never be shown")
	}
	b, _ := os.ReadFile(envPath) // #nosec G304 -- test temp file
	if want := strings.Replace(envBody, g.keyB64, newB64, 1); string(b) != want {
		t.Fatalf("only the key line may change:\n%s", b)
	}
	if info, err := os.Stat(envPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("env file mode must stay 0600: %v %v", info, err)
	}
	if ringOpensWith(t, g, g.key) {
		t.Fatal("the old key must no longer open the ring")
	}
	g.key, g.keyB64 = newKey, newB64
	g.with(t, func(ctx context.Context, db *store.DB, ring *keyring.Ring) {
		opened, err := credential.NewVault(db, ring).Open(ctx, credID)
		if err != nil || opened.Password != "survives-rewrap" {
			t.Fatalf("secret after rewrap: %v", err)
		}
		opened.Close()
	})
	ev := lastAudit(t, g, "key.rotate_master")
	var d map[string]any
	_ = json.Unmarshal(ev.Details, &d)
	if d["env_file_updated"] != true || d["key_file_updated"] != false || d["versions_rewrapped"] != float64(1) {
		t.Fatalf("audit details %v", d)
	}
	if bytes.Contains(ev.Details, []byte(newB64)) {
		t.Fatal("the audit event must not carry the key")
	}
}

// TestRotateMasterWithoutAFile: with no file to update the new key comes from
// ZANSKAR_NEW_MASTER_KEY (and is not echoed back) or from -generate, in which
// case it is printed once because it is stored nowhere else.
func TestRotateMasterWithoutAFile(t *testing.T) {
	g := newCLIGateway(t, true)

	given, givenKey := randomKeyB64(t)
	t.Setenv("ZANSKAR_NEW_MASTER_KEY", given)
	out, _, err := output(t, func() error { return runKeyRotateMaster([]string{"-yes"}) })
	if err != nil || !strings.Contains(out, "put the new key in the service's environment") || strings.Contains(out, given) {
		t.Fatalf("rotate with a supplied key: %v\n%s", err, out)
	}
	if !ringOpensWith(t, g, givenKey) || ringOpensWith(t, g, g.key) {
		t.Fatal("the supplied key must now be the only one that opens the ring")
	}
	g.key, g.keyB64 = givenKey, given
	t.Setenv("ZANSKAR_MASTER_KEY", given)
	t.Setenv("ZANSKAR_NEW_MASTER_KEY", "")

	out, _, err = output(t, func() error { return runKeyRotateMaster([]string{"-generate", "-yes"}) })
	if err != nil {
		t.Fatalf("rotate -generate: %v", err)
	}
	m := regexp.MustCompile(`(?m)^([A-Za-z0-9+/]{43}=)$`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("-generate without a file must print the new key:\n%s", out)
	}
	printed, _ := base64.StdEncoding.DecodeString(m[1])
	if !ringOpensWith(t, g, printed) || ringOpensWith(t, g, givenKey) {
		t.Fatal("the printed key must be the one the ring is now under")
	}
}

// TestRotateMasterKeyFileUnwritable: a named key file whose directory cannot
// be written is refused before the rewrap, so the database is never left
// under a key that exists nowhere.
func TestRotateMasterKeyFileUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	g := newCLIGateway(t, true)
	t.Setenv("ZANSKAR_NEW_MASTER_KEY", "")
	locked := filepath.Join(g.dir, "locked")
	if err := os.MkdirAll(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(locked, "master.key")
	if err := os.WriteFile(keyPath, []byte(g.keyB64+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	_, _, err := output(t, func() error { return runKeyRotateMaster([]string{"-key-file", keyPath, "-generate", "-yes"}) })
	if err == nil || !strings.Contains(err.Error(), "nothing was changed") || !strings.Contains(err.Error(), locked) {
		t.Fatalf("want a refusal naming the directory, got %v", err)
	}
	if !ringOpensWith(t, g, g.key) {
		t.Fatal("the old key must still open the ring")
	}
}

// TestReplaceKeyFileAndCheckReplaceable: the helpers refuse a missing file
// rather than creating one.
func TestReplaceKeyFileAndCheckReplaceable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.key")
	if err := checkReplaceable(missing); err == nil {
		t.Fatal("checkReplaceable must fail for a missing file")
	}
	if err := replaceKeyFile(missing, "x"); err == nil {
		t.Fatal("replaceKeyFile must fail for a missing file")
	}
	if err := replaceEnvMasterKey(missing, "x"); err == nil {
		t.Fatal("replaceEnvMasterKey must fail for a missing file")
	}
	if _, err := os.Stat(missing); err == nil {
		t.Fatal("no file may be created")
	}
	if firstN("abc", 16) != "abc" || orDash("") != "-" || orDash("x") != "x" {
		t.Fatal("formatting helpers")
	}
}
