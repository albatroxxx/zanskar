// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"errors"
	"testing"
)

// The security contact becomes a line of /.well-known/security.txt; nothing
// an administrator types may add a line of its own (2026-11-03 live audit, S1).
func TestSecurityContactURI(t *testing.T) {
	for in, want := range map[string]string{
		"security@example.com":                        "mailto:security@example.com",
		" mailto:security@example.com ":               "mailto:security@example.com",
		"https://example.com/security":                "https://example.com/security",
		"http://example.com/security":                 "",
		"https://user:pw@example.com/":                "",
		"security@example.com\nPolicy: https://x.com": "",
		"https://example.com/\r\nHiring: yes":         "",
		"not an address":                              "",
		"https://example.com/a b":                     "",
		"https://example.com/<script>":                "",
		`https://example.com/"q"`:                     "",
		"javascript:alert(1)":                         "",
		"":                                            "",
	} {
		if got := SecurityContactURI(in); got != want {
			t.Errorf("SecurityContactURI(%q) = %q, want %q", in, got, want)
		}
	}
	d := Definition{Key: KeySecurityContact, Type: TypeString}
	if v, err := Validate(d, ""); err != nil || v != "" {
		t.Fatalf("empty must be allowed (publishes nothing): %q %v", v, err)
	}
	if _, err := Validate(d, "security@example.com\nExpires: 2099"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a second line must be refused: %v", err)
	}
	if v, err := Validate(d, "https://example.com/report"); err != nil || v != "https://example.com/report" {
		t.Fatalf("an https page: %q %v", v, err)
	}
}
