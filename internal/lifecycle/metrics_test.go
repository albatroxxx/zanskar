// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"os"
	"testing"
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
