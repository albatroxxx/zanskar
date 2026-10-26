// SPDX-License-Identifier: Apache-2.0

package update

import (
	"testing"
)

// FuzzVersionParse: whatever text a manifest or a request carries as a
// version, Canonical either refuses it or rebuilds a version that reads
// back to itself, is bounded, and holds no control character — a log line
// and the update request file carry only that form.
func FuzzVersionParse(f *testing.F) {
	for _, s := range []string{"1.2.3", "v1.2.3", "1.2.3-rc.1", "1.2", "1.2.3.4", "-1.2.3", "1.2.3-", "1.2.3-\n", "01.002.0003", "9999999999999999999.0.0", "1.2.3-" + string(make([]byte, 65)), "", " 1.2.3 "} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		c := Canonical(in)
		if c == "" {
			if IsVersion(in) {
				t.Fatalf("IsVersion(%q) but Canonical is empty", in)
			}
			return
		}
		if !IsVersion(c) || Canonical(c) != c {
			t.Fatalf("Canonical(%q) = %q does not read back", in, c)
		}
		if len(c) > 128 {
			t.Fatalf("Canonical(%q) is %d bytes", in, len(c))
		}
		for i := 0; i < len(c); i++ {
			if c[i] < 0x20 || c[i] > 0x7e {
				t.Fatalf("Canonical(%q) = %q holds byte %#x", in, c, c[i])
			}
		}
		if Newer(c, c) {
			t.Fatalf("%q is newer than itself", c)
		}
		if Newer(in, c) || Newer(c, in) {
			t.Fatalf("%q and its canonical form %q order differently", in, c)
		}
	})
}
