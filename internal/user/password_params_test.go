// SPDX-License-Identifier: Apache-2.0

package user

import (
	"strings"
	"testing"
)

// TestProductionParametersStandAndVerify: tests hash with reduced
// parameters so the suites that sign in stay fast (review Q1, finding 3);
// the production constants must still sit at or above the OWASP argon2id
// floor (19 MiB, 2 passes) and a hash made with them must verify and read
// as current, not as one to upgrade.
func TestProductionParametersStandAndVerify(t *testing.T) {
	prod := productionParams()
	if prod.memory < 19*1024 || prod.time < 2 || prod.threads < 1 {
		t.Fatalf("production argon2id parameters below the OWASP floor: %+v", prod)
	}
	if hashParams.memory >= prod.memory {
		t.Fatalf("the test binary is hashing at production cost (%+v); the knob is off", hashParams)
	}
	h, err := hashPasswordWith("correct horse battery staple", prod)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Fatalf("production hash prefix: %s", h)
	}
	if !VerifyPassword(h, "correct horse battery staple") || VerifyPassword(h, "wrong") {
		t.Fatal("a production-strength hash must verify its password and no other")
	}
	if NeedsRehash(h) {
		t.Fatal("a production-strength hash must not be marked for rehash under test parameters")
	}
	// A hash made under test parameters is one production would upgrade:
	// the comparison is against what this binary hashes with, so a test
	// never sees its own hashes as stale, and the check still bites below.
	if !NeedsRehash("$argon2id$v=19$m=4096,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") {
		t.Fatal("a weaker hash must be marked for rehash")
	}
}
