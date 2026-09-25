// SPDX-License-Identifier: Apache-2.0

package user

import (
	"strings"
	"testing"
)

// FuzzParsePHC: hostile hash strings from the database must never panic,
// and anything accepted must carry sane parameters (the memory bound is
// what stops a crafted row from making VerifyPassword allocate gigabytes).
func FuzzParsePHC(f *testing.F) {
	f.Add("$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG")
	f.Add("$argon2id$v=19$m=0,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub")
	f.Add("$argon2id$v=19$m=99999999999,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub")
	f.Add("$argon2i$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub")
	f.Add("$$$$$")
	f.Add("")
	f.Fuzz(func(t *testing.T, hash string) {
		p, salt, key, err := parsePHC(hash)
		if err != nil {
			return
		}
		if p.memory == 0 || p.memory > 1<<22 || p.time == 0 || p.threads == 0 {
			t.Fatalf("accepted out-of-range params %+v from %q", p, hash)
		}
		if len(key) == 0 {
			t.Fatalf("accepted empty key from %q", hash)
		}
		_ = salt
		if strings.Count(hash, "$") != 5 {
			t.Fatalf("accepted hash with %d separators: %q", strings.Count(hash, "$"), hash)
		}
	})
}

// FuzzVerifyPassword: only the exact password verifies against its hash.
func FuzzVerifyPassword(f *testing.F) {
	const pw = "correct horse battery staple 2026"
	hash, err := HashPassword(pw)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(pw)
	f.Add(pw + " ")
	f.Add("")
	f.Add("Correct horse battery staple 2026")
	f.Fuzz(func(t *testing.T, candidate string) {
		if got := VerifyPassword(hash, candidate); got != (candidate == pw) {
			t.Fatalf("VerifyPassword(hash, %q) = %v", candidate, got)
		}
	})
}
