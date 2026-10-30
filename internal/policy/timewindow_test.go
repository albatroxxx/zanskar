// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"testing"
	"time"
)

func TestTimeWindow(t *testing.T) {
	w := TimeWindow{Days: []string{"mon", "tue"}, From: "09:00", To: "18:00", TZ: "UTC"}
	if err := w.validate(); err != nil {
		t.Fatal(err)
	}
	mon10 := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC) // Monday
	mon19 := time.Date(2026, 9, 21, 19, 0, 0, 0, time.UTC)
	wed10 := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	if !w.Open(mon10) || w.Open(mon19) || w.Open(wed10) {
		t.Fatal("daytime window wrong")
	}
	night := TimeWindow{Days: []string{"fri"}, From: "22:00", To: "06:00", TZ: "Asia/Kolkata"}
	if err := night.validate(); err != nil {
		t.Fatal(err)
	}
	loc, _ := time.LoadLocation("Asia/Kolkata")
	fri23 := time.Date(2026, 9, 25, 23, 0, 0, 0, loc)
	sat03 := time.Date(2026, 9, 26, 3, 0, 0, 0, loc)
	sat07 := time.Date(2026, 9, 26, 7, 0, 0, 0, loc)
	thu23 := time.Date(2026, 9, 24, 23, 0, 0, 0, loc)
	if !night.Open(fri23) || !night.Open(sat03) || night.Open(sat07) || night.Open(thu23) {
		t.Fatal("overnight window wrong")
	}
	bad := TimeWindow{Days: []string{"funday"}, From: "09:00", To: "18:00"}
	if err := bad.validate(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("expected invalid day")
	}
	bad = TimeWindow{Days: []string{"mon"}, From: "9am", To: "18:00"}
	if err := bad.validate(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("expected invalid clock")
	}
}

// TestWindowWithEqualEndsIsAllDay: a window from 00:00 to 00:00 never opened
// (B18): from == to was read as an empty span, and nothing said so. Equal
// ends now mean the whole of each listed day, which is what 00:00 to 00:00
// is written to say.
func TestWindowWithEqualEndsIsAllDay(t *testing.T) {
	for _, clock := range []string{"00:00", "09:30"} {
		w := TimeWindow{Days: []string{"mon"}, From: clock, To: clock, TZ: "UTC"}
		if err := w.validate(); err != nil {
			t.Fatal(err)
		}
		monday := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC) // a Monday
		for _, at := range []time.Duration{0, 9*time.Hour + 29*time.Minute, 23*time.Hour + 59*time.Minute} {
			if !w.Open(monday.Add(at)) {
				t.Fatalf("%s to %s: closed on Monday at %s", clock, clock, monday.Add(at).Format("15:04"))
			}
		}
		if w.Open(monday.Add(24*time.Hour + time.Hour)) {
			t.Fatalf("%s to %s: open on Tuesday, which is not listed", clock, clock)
		}
	}
}
