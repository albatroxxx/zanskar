// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"strings"
	"testing"
	"time"
)

// 2026-11-03 live audit, idea 8: the live gateway's disk was 72% full with
// recordings, images and the database on it. Past 95% new sessions are
// refused, in words, so none runs unrecorded; below it, nothing changes.
func TestDiskGuard(t *testing.T) {
	const gb = 1 << 30
	disks := []DiskSpace{{What: "database & recordings", UsedBytes: 94 * gb, FreeBytes: 6 * gb}}
	calls := 0
	g := &DiskGuard{measure: func(string, string) []DiskSpace { calls++; return disks }}
	if msg := g.Full(); msg != "" {
		t.Fatalf("94%% used refused: %q", msg)
	}
	// A reading stands for a while; a full disk is seen once it lapses.
	disks = []DiskSpace{{What: "database & recordings", UsedBytes: 95 * gb, FreeBytes: 5 * gb}}
	if msg := g.Full(); msg != "" || calls != 1 {
		t.Fatalf("a fresh reading was measured again: %q, %d calls", msg, calls)
	}
	g.at = time.Now().Add(-diskGuardEvery)
	msg := g.Full()
	if !strings.HasPrefix(msg, "the gateway's database & recordings disk is 95% full; new sessions are refused") {
		t.Fatalf("95%% used: %q", msg)
	}
	// Any one volume full is enough.
	disks = []DiskSpace{{What: "database", UsedBytes: 1, FreeBytes: 99}, {What: "recordings", UsedBytes: 99, FreeBytes: 1}}
	g.at = time.Time{}
	if msg := g.Full(); !strings.Contains(msg, "recordings disk is 99% full") {
		t.Fatalf("a full recordings volume: %q", msg)
	}
	// Nothing measured (Postgres, recordings in S3): nothing refused.
	disks, g.at = nil, time.Time{}
	if msg := g.Full(); msg != "" {
		t.Fatalf("no volumes: %q", msg)
	}
	var none *DiskGuard
	if none.Full() != "" {
		t.Fatal("a nil guard refuses")
	}
}

func TestUsedPercentRoundsUpAsDfDoes(t *testing.T) {
	for _, c := range []struct {
		used, free uint64
		want       int
	}{{0, 100, 0}, {1, 99, 1}, {949, 51, 95}, {941, 59, 95}, {940, 60, 94}, {100, 0, 100}, {0, 0, 0}} {
		if got := usedPercent(DiskSpace{UsedBytes: c.used, FreeBytes: c.free}); got != c.want {
			t.Errorf("used %d free %d: %d%%, want %d%%", c.used, c.free, got, c.want)
		}
	}
}
