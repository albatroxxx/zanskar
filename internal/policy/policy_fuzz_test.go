// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"testing"
)

// FuzzParseClock: anything accepted is a minute of the day and formats
// back to a string that parses to the same minute.
func FuzzParseClock(f *testing.F) {
	f.Add("09:30")
	f.Add("23:59")
	f.Add("24:00")
	f.Add("9:30")
	f.Add("+1:05")
	f.Add("1e:05")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		v, err := parseClock(s)
		if err != nil {
			return
		}
		if v < 0 || v >= 24*60 {
			t.Fatalf("parseClock(%q) = %d, out of range", s, v)
		}
		canon := fmt.Sprintf("%02d:%02d", v/60, v%60)
		again, err := parseClock(canon)
		if err != nil || again != v {
			t.Fatalf("canonical %q re-parsed to %d, %v (want %d)", canon, again, err, v)
		}
	})
}
