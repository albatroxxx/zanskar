// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
