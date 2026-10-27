// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMasterKeyFromReadsTheServiceSyntax: init reads the existing key the
// way the service does, so a line written as `export ZANSKAR_MASTER_KEY=...`
// or with quotes is a key `init --force` preserves, not one it replaces
// (review finding SEC-4).
func TestMasterKeyFromReadsTheServiceSyntax(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"export":  "export ZANSKAR_MASTER_KEY=deadbeef==\n",
		"quoted":  "ZANSKAR_MASTER_KEY=\"deadbeef==\"\n",
		"single":  "export ZANSKAR_MASTER_KEY='deadbeef=='\n",
		"spaced":  "  ZANSKAR_MASTER_KEY = deadbeef==  \n",
		"between": "# key\n; note\nZANSKAR_LISTEN_ADDR=x\n\nZANSKAR_MASTER_KEY=deadbeef==\nZANSKAR_GUACD_ADDR=y\n",
	} {
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := masterKeyFrom(f); got != "deadbeef==" {
			t.Errorf("%s: masterKeyFrom = %q, want deadbeef==", name, got)
		}
		if keyLineUnreadable(f) {
			t.Errorf("%s: a readable key line reported unreadable", name)
		}
	}
}

// TestInitForcePreservesAnExportedKey: the file the operator hand-wrote with
// an export prefix keeps its key through `init --force`; before the fix init
// minted a fresh key over it and the stored secrets were lost with the old
// one.
func TestInitForcePreservesAnExportedKey(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "env")
	keyB64, _ := randomKeyB64(t)
	if err := os.WriteFile(env, []byte("export ZANSKAR_LISTEN_ADDR=127.0.0.1:8443\nexport ZANSKAR_MASTER_KEY=\""+keyB64+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, err := output(t, func() error {
		return runInit([]string{"--print", "--non-interactive", "--force", "--out", env, "--data-dir", filepath.Join(dir, "data")})
	})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if !strings.Contains(stdout, "ZANSKAR_MASTER_KEY="+keyB64+"\n") {
		t.Errorf("the exported key was not preserved:\n%s", stdout)
	}
	if strings.Count(stdout, "ZANSKAR_MASTER_KEY=") != 1 {
		t.Errorf("more than one key line:\n%s", stdout)
	}
}

// TestInitRefusesAKeyLineItCannotRead: a ZANSKAR_MASTER_KEY line the parser
// yields no value for is not replaced with a new key; init says what to
// write instead. A commented-out line is not a key line.
func TestInitRefusesAKeyLineItCannotRead(t *testing.T) {
	dir := t.TempDir()
	run := func(body string) (string, error) {
		env := filepath.Join(dir, "env")
		if err := os.WriteFile(env, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		stdout, _, err := output(t, func() error {
			return runInit([]string{"--print", "--non-interactive", "--force", "--out", env, "--data-dir", filepath.Join(dir, "data")})
		})
		return stdout, err
	}
	for name, body := range map[string]string{
		"no equals": "ZANSKAR_MASTER_KEY deadbeef==\n",
		"empty":     "ZANSKAR_MASTER_KEY=\n",
		"exported":  "export ZANSKAR_MASTER_KEY\n",
	} {
		if _, err := run(body); err == nil || !strings.Contains(err.Error(), "cannot read") {
			t.Errorf("%s: want a refusal naming the unreadable line, got %v", name, err)
		}
	}
	stdout, err := run("# ZANSKAR_MASTER_KEY=old\nZANSKAR_LISTEN_ADDR=127.0.0.1:8443\n")
	if err != nil {
		t.Fatalf("a commented key line must not block init: %v", err)
	}
	if !strings.Contains(stdout, "ZANSKAR_MASTER_KEY=") || strings.Contains(stdout, "ZANSKAR_MASTER_KEY=old") {
		t.Errorf("a commented key line must be ignored and a fresh key minted:\n%s", stdout)
	}
}
