// SPDX-License-Identifier: Apache-2.0

package auth

import "testing"

// FuzzParseAddr: accepted addresses are canonical (never IPv4-mapped) and
// round-trip through their own String form.
func FuzzParseAddr(f *testing.F) {
	f.Add("10.0.0.1")
	f.Add("10.0.0.1:8443")
	f.Add("::ffff:10.0.0.1")
	f.Add("[::1]:443")
	f.Add("[fe80::1%eth0]:22")
	f.Add("not an address")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		addr, ok := parseAddr(s)
		if !ok {
			return
		}
		if !addr.IsValid() {
			t.Fatalf("parseAddr(%q) ok with invalid addr", s)
		}
		if addr.Is4In6() {
			t.Fatalf("parseAddr(%q) returned an IPv4-mapped address %v", s, addr)
		}
		again, ok := parseAddr(addr.String())
		if !ok || again != addr {
			t.Fatalf("round trip of %v via %q gave %v, %v", addr, addr.String(), again, ok)
		}
	})
}
