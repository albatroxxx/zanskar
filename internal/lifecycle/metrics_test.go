// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"os"
	"testing"
	"time"
)

func TestParseLoadavg(t *testing.T) {
	got := parseLoadavg("0.42 1.5 2.25 2/345 6789\n")
	if got == nil || got.One != 0.42 || got.Five != 1.5 || got.Fifteen != 2.25 {
		t.Fatalf("parseLoadavg = %+v", got)
	}
	if parseLoadavg("not numbers at all") != nil {
		t.Fatal("garbage parsed as load averages")
	}
	if parseLoadavg("") != nil {
		t.Fatal("empty parsed as load averages")
	}
}

func TestParseMeminfo(t *testing.T) {
	got := parseMeminfo("MemTotal:       16384000 kB\nMemFree:         1000000 kB\nMemAvailable:    8192000 kB\nBuffers:          123456 kB\n")
	if got == nil || got.TotalBytes != 16384000*1024 || got.AvailableBytes != 8192000*1024 {
		t.Fatalf("parseMeminfo = %+v", got)
	}
	if parseMeminfo("Buffers: 1 kB\n") != nil {
		t.Fatal("meminfo without MemTotal parsed")
	}
}

// TestDiskSpace: a real filesystem answers with non-zero sizes, two paths on
// the same filesystem fold into one entry, and a missing path is skipped
// rather than reported as a zero-byte volume.
func TestDiskSpace(t *testing.T) {
	dir := t.TempDir()
	one := diskSpace(dir, "")
	if len(one) != 1 || one[0].What != "database" || one[0].TotalBytes == 0 {
		t.Fatalf("one path: %+v", one)
	}
	// df's Used and Avail: neither exceeds the size, and together they
	// leave out at most the root-reserved blocks.
	if d := one[0]; d.UsedBytes == 0 || d.UsedBytes+d.FreeBytes > d.TotalBytes {
		t.Fatalf("used and free do not fit the size: %+v", d)
	}
	// A temp dir usually shares the root filesystem; when it does, the entry
	// says so, and the console will call it the system disk.
	if rootInfo, err := os.Stat("/"); err == nil {
		if tmpInfo, err2 := os.Stat(dir); err2 == nil && deviceID(rootInfo) == deviceID(tmpInfo) && !one[0].System {
			t.Fatalf("root-filesystem path not marked system: %+v", one[0])
		}
	}
	both := diskSpace(dir, dir)
	if len(both) != 1 || both[0].What != "database & recordings" {
		t.Fatalf("same filesystem: %+v", both)
	}
	none := diskSpace("", dir+"/does-not-exist")
	if len(none) != 0 {
		t.Fatalf("missing paths: %+v", none)
	}
}

// TestParseCPUStat: the aggregate line's jiffies, busy excluding idle and
// iowait; other lines and a short line are passed over.
func TestParseCPUStat(t *testing.T) {
	at := time.Now()
	s, ok := parseCPUStat("cpu  100 0 50 800 40 5 5 0 0 0\ncpu0 1 2 3 4 5 6 7 8 9 10\n", at)
	if !ok || s.total != 1000 || s.busy != 160 || !s.at.Equal(at) {
		t.Fatalf("got %+v %v", s, ok)
	}
	if _, ok := parseCPUStat("cpu0 1 2 3 4\nintr 5\n", at); ok {
		t.Fatal("no aggregate line parsed")
	}
	if _, ok := parseCPUStat("cpu x 2 3 4 5\n", at); ok {
		t.Fatal("a bad number parsed")
	}
}

// TestCPUSamplerWindows: the first request measures a short window of its
// own, a later request measures since the previous one, a request within
// a second repeats the last answer, and a host without /proc/stat answers
// nothing.
func TestCPUSamplerWindows(t *testing.T) {
	base := time.Now().Add(-10 * time.Second)
	seq := []cpuSample{
		{busy: 100, total: 1000, at: base},
		{busy: 150, total: 1100, at: base.Add(200 * time.Millisecond)},  // 50 of 100 busy
		{busy: 170, total: 1300, at: base.Add(5200 * time.Millisecond)}, // 20 of 200 busy
	}
	i := 0
	var slept time.Duration
	c := &cpuSampler{read: func() (*cpuSample, bool) {
		s := seq[i]
		i++
		return &s, true
	}, sleep: func(d time.Duration) { slept += d }}
	u := c.usage()
	if u == nil || u.Percent != 50 || slept != cpuFirstWindow || u.WindowSeconds < 0.19 || u.WindowSeconds > 0.21 {
		t.Fatalf("first: %+v slept %v", u, slept)
	}
	// The second sample is ten seconds old by the clock, so the next
	// request measures against it.
	u = c.usage()
	if u == nil || u.Percent != 10 || u.WindowSeconds < 4.9 || u.WindowSeconds > 5.1 {
		t.Fatalf("second: %+v", u)
	}
	// Within a second of the last reading: the last answer, no new reading.
	c.last.at = time.Now()
	if again := c.usage(); again != u || i != 3 {
		t.Fatalf("a request within a second re-read: %+v reads=%d", again, i)
	}
	none := &cpuSampler{read: func() (*cpuSample, bool) { return nil, false }, sleep: func(time.Duration) {}}
	if u := none.usage(); u != nil {
		t.Fatalf("no /proc/stat answered %+v", u)
	}
}

// TestCPUSamplerRebaselinesAStaleReading (2026-10-30): reopening the
// dashboard after an hour showed the hour's average as the first figure,
// because the window ran from the last request, whenever that was. A
// reading older than cpuStaleAfter starts a fresh pair instead.
func TestCPUSamplerRebaselinesAStaleReading(t *testing.T) {
	now := time.Now()
	seq := []cpuSample{
		{busy: 100, total: 1000, at: now.Add(-time.Hour)},
		{busy: 900, total: 2000, at: now},                             // the hour: 80% busy
		{busy: 910, total: 2100, at: now.Add(200 * time.Millisecond)}, // now: 10% busy
	}
	i := 0
	var slept time.Duration
	c := &cpuSampler{read: func() (*cpuSample, bool) {
		s := seq[i]
		i++
		return &s, true
	}, sleep: func(d time.Duration) { slept += d }}
	c.last = &seq[0]
	i = 1
	u := c.usage()
	if u == nil || u.Percent != 10 || slept != cpuFirstWindow {
		t.Fatalf("a stale baseline was measured across: %+v slept %v", u, slept)
	}
}
