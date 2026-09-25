// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"strings"
	"testing"
)

// FuzzParseConsoleHostKeys: fingerprints are only ever taken from inside
// the BEGIN/END block, are unique, and match the fingerprint grammar.
func FuzzParseConsoleHostKeys(f *testing.F) {
	fp := "SHA256:Ys3rdwo+SClvcDNfmfZDgMJL6IzyGgH27DctbvUsZQY"
	f.Add("-----BEGIN SSH HOST KEY FINGERPRINTS-----\n256 "+fp+" root@host (ED25519)\n-----END SSH HOST KEY FINGERPRINTS-----\n", "")
	f.Add("ec2: -----BEGIN SSH HOST KEY FINGERPRINTS-----\nec2: 256 "+fp+" root@host (ED25519)\nec2: -----END SSH HOST KEY FINGERPRINTS-----", fp)
	f.Add("no block here "+fp, "")
	f.Fuzz(func(t *testing.T, console, planted string) {
		out := ParseConsoleHostKeys(console)
		if !strings.Contains(console, "BEGIN SSH HOST KEY FINGERPRINTS") && out != nil {
			t.Fatalf("returned %v without a BEGIN marker", out)
		}
		seen := map[string]bool{}
		for _, got := range out {
			if !fingerprintRe.MatchString(got) {
				t.Fatalf("result %q does not match the fingerprint grammar", got)
			}
			if seen[got] {
				t.Fatalf("duplicate result %q", got)
			}
			seen[got] = true
		}
		// A fingerprint appended after the END marker must never be picked up.
		if fingerprintRe.MatchString(planted) {
			tail := console + "\n-----END SSH HOST KEY FINGERPRINTS-----\n" + planted
			for _, got := range ParseConsoleHostKeys(tail) {
				if got == planted && !strings.Contains(console, planted) {
					t.Fatalf("planted fingerprint %q outside the block was accepted", planted)
				}
			}
		}
	})
}
