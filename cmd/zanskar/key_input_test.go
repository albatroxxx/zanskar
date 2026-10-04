// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// TestNewMasterKeyInput: rotate-master takes the new key from
// ZANSKAR_NEW_MASTER_KEY (scripts), generates a fresh 32-byte one when asked,
// and otherwise needs a terminal to prompt on; it never takes the key from
// a pipe, where it would end up in shell history or a process listing.
func TestNewMasterKeyInput(t *testing.T) {
	t.Setenv("ZANSKAR_NEW_MASTER_KEY", "  from-the-environment  ")
	if k, err := newMasterKeyInput(true); err != nil || k != "from-the-environment" {
		t.Fatalf("environment key: %q %v (it wins over -generate, trimmed)", k, err)
	}

	t.Setenv("ZANSKAR_NEW_MASTER_KEY", "")
	a, err := newMasterKeyInput(true)
	b, _ := newMasterKeyInput(true)
	raw, derr := base64.StdEncoding.DecodeString(a)
	if err != nil || derr != nil || len(raw) != 32 || a == b {
		t.Fatalf("generated keys %q %q: %v %v", a, b, err, derr)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = saved; _ = r.Close(); _ = w.Close() })
	if _, err := newMasterKeyInput(false); err == nil || !strings.Contains(err.Error(), "no terminal") {
		t.Fatalf("no terminal: %v", err)
	}
}
