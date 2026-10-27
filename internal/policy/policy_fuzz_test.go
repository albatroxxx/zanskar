// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"strconv"
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
	f.Add("00:30")
	f.Add("13:07")
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
		// A well-formed HH:MM must mean its hour and its minute: a parser
		// that dropped the hour would still pass the round trip above.
		if len(s) == 5 && s[2] == ':' {
			hh, errH := strconv.Atoi(s[:2])
			mm, errM := strconv.Atoi(s[3:])
			if errH == nil && errM == nil && hh < 24 && mm < 60 && v != hh*60+mm {
				t.Fatalf("parseClock(%q) = %d, want %d", s, v, hh*60+mm)
			}
		}
	})
}
