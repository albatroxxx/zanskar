// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
)

// TestReplaceEnvMasterKey: only the key line changes, every other line and
// the file mode survive, and a file without the line is refused.
func TestReplaceEnvMasterKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env")
	oldKey := make([]byte, 32)
	newKey := make([]byte, 32)
	if _, err := rand.Read(oldKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(newKey); err != nil {
		t.Fatal(err)
	}
	oldB64, newB64 := base64.StdEncoding.EncodeToString(oldKey), base64.StdEncoding.EncodeToString(newKey)
	content := "# zanskar\nZANSKAR_LISTEN_ADDR=127.0.0.1:8443\n" + "ZANSKAR_MASTER_KEY=" + oldB64 + "\nZANSKAR_GUACD_ADDR=127.0.0.1:4822\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceEnvMasterKey(path, newB64); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	want := "# zanskar\nZANSKAR_LISTEN_ADDR=127.0.0.1:8443\n" + "ZANSKAR_MASTER_KEY=" + newB64 + "\nZANSKAR_GUACD_ADDR=127.0.0.1:4822\n"
	if string(got) != want {
		t.Fatalf("env after replace:\n%s", got)
	}
	if strings.Contains(string(got), oldB64) {
		t.Fatal("old key must be gone")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode must be kept: %v %v", info.Mode(), err)
	}
	if masterKeyFrom(path) != newB64 {
		t.Fatal("init's reader must see the new key")
	}

	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("ZANSKAR_LISTEN_ADDR=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceEnvMasterKey(other, newB64); err == nil {
		t.Fatal("a file without the key line must be refused")
	}
}

// TestRotateMasterKeyFile: with the key in ZANSKAR_MASTER_KEY_FILE, rotation
// rewraps the ring, replaces the file's key in place (mode kept) and never
// needs -env-file; the database then opens under the new key only.
func TestRotateMasterKeyFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "z.db") + "?_pragma=foreign_keys(1)"
	oldKey := make([]byte, 32)
	if _, err := rand.Read(oldKey); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(oldKey)+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZANSKAR_DB_DSN", dsn)
	t.Setenv("ZANSKAR_MASTER_KEY", "")
	t.Setenv("ZANSKAR_MASTER_KEY_FILE", keyPath)
	t.Setenv("ZANSKAR_NEW_MASTER_KEY", "")

	db, err := store.Open(ctx, "sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	kek, _ := crypto.NewLocalKEK(oldKey)
	ring, err := keyring.Open(ctx, db, kek)
	if err != nil {
		t.Fatal(err)
	}
	ring.Close()
	_ = db.Close()

	// A key file that cannot be replaced is refused before anything is
	// rewrapped: afterwards the new key would exist nowhere.
	if os.Geteuid() != 0 { // root writes anywhere, so the check cannot fail
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		err := runKeyRotateMaster([]string{"-generate", "-yes"})
		_ = os.Chmod(dir, 0o700)
		if err == nil || !strings.Contains(err.Error(), "nothing was changed") {
			t.Fatalf("want a refusal before the rewrap, got %v", err)
		}
		db, err := store.Open(ctx, "sqlite", dsn)
		if err != nil {
			t.Fatal(err)
		}
		r, err := keyring.Open(ctx, db, kek)
		if err != nil {
			t.Fatalf("the old key must still open the ring after a refused rotation: %v", err)
		}
		r.Close()
		_ = db.Close()
	}

	// -env-file is refused: the file is the key's home.
	if err := runKeyRotateMaster([]string{"-env-file", filepath.Join(dir, "env"), "-generate", "-yes"}); err == nil || !strings.Contains(err.Error(), "drop -env-file") {
		t.Fatalf("want the -env-file refusal, got %v", err)
	}
	if err := runKeyRotateMaster([]string{"-generate", "-yes"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("key file mode must be kept: %v %v", info.Mode(), err)
	}
	b, _ := os.ReadFile(keyPath) // #nosec G304 -- test temp file
	newKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(newKey) != 32 || string(newKey) == string(oldKey) {
		t.Fatalf("key file must hold a new 32-byte key: %v", err)
	}

	db, err = store.Open(ctx, "sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := keyring.Open(ctx, db, kek); err == nil {
		t.Fatal("the old key must no longer open the ring")
	}
	newKEK, _ := crypto.NewLocalKEK(newKey)
	r2, err := keyring.Open(ctx, db, newKEK)
	if err != nil {
		t.Fatalf("the new key must open the ring: %v", err)
	}
	r2.Close()
}
