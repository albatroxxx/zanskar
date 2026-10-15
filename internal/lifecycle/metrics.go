// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/albatroxxx/zanskar/internal/httpx"
)

// Metrics is the host's numbers right now, for the admin dashboard's gateway
// card: facts with thresholds in the console, never history — time series
// belong to an exporter (ADR 0031, proposed). Fields the host cannot answer
// (no /proc off Linux, no guacd address configured) are omitted, not faked.
type Metrics struct {
	Load   *LoadAverages `json:"load,omitempty"`
	Memory *MemoryInfo   `json:"memory,omitempty"`
	Disks  []DiskSpace   `json:"disks"`
	// DatabaseSessions is how many database client containers this process
	// is running right now: each live database session is one (ADR 0017).
	// Counted from the session registry, so no Docker socket is needed.
	DatabaseSessions int         `json:"database_sessions"`
	Guacd            *GuacdCheck `json:"guacd,omitempty"`
	// CPUs scales the load average into a meter: a load of 4 is calm on 16
	// cores and saturation on 4.
	CPUs int `json:"cpus"`
}

// LoadAverages are /proc/loadavg's three numbers.
type LoadAverages struct {
	One     float64 `json:"one"`
	Five    float64 `json:"five"`
	Fifteen float64 `json:"fifteen"`
}

// MemoryInfo is the host's memory: total and what is still available to
// allocate (MemAvailable, which accounts for reclaimable cache).
type MemoryInfo struct {
	TotalBytes     uint64 `json:"total_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}

// DiskSpace is one volume the gateway writes: the database, the recordings,
// or both when they share a filesystem. A full recordings volume stops
// sessions being recorded, which is why it is on the dashboard.
type DiskSpace struct {
	What string `json:"what"`
	Path string `json:"path"`
	// System says this location sits on the root filesystem, so the numbers
	// are the OS disk's — the common single-disk install. The console names
	// it "System disk" then, instead of implying a separate volume.
	System     bool   `json:"system"`
	TotalBytes uint64 `json:"total_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
}

// GuacdCheck says whether the desktop relay answers at its configured
// address; without it RDP and VNC sessions cannot open.
type GuacdCheck struct {
	Address   string `json:"address"`
	Reachable bool   `json:"reachable"`
}

// guacdDialTimeout bounds the reachability check; guacd is on the same box
// or LAN, so an answer takes milliseconds or is not coming.
const guacdDialTimeout = 800 * time.Millisecond

func (h *Handler) metrics(w http.ResponseWriter, r *http.Request) {
	m := Metrics{
		Load:   readLoadavg(),
		Memory: readMeminfo(),
		Disks:  diskSpace(h.DatabasePath, h.RecordingsPath),
		CPUs:   runtime.NumCPU(),
	}
	if h.Controller != nil && h.Controller.Registry != nil {
		for _, l := range h.Controller.Registry.List() {
			if l.Protocol == "database" {
				m.DatabaseSessions++
			}
		}
	}
	if h.GuacdAddr != nil {
		if addr := strings.TrimSpace(h.GuacdAddr()); addr != "" {
			check := &GuacdCheck{Address: addr}
			d := net.Dialer{Timeout: guacdDialTimeout}
			if conn, err := d.DialContext(r.Context(), "tcp", addr); err == nil {
				check.Reachable = true
				_ = conn.Close()
			}
			m.Guacd = check
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, m)
}

// readLoadavg parses /proc/loadavg; nil anywhere the file does not exist.
func readLoadavg() *LoadAverages {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil
	}
	return parseLoadavg(string(b))
}

func parseLoadavg(s string) *LoadAverages {
	f := strings.Fields(s)
	if len(f) < 3 {
		return nil
	}
	var out LoadAverages
	var err error
	if out.One, err = strconv.ParseFloat(f[0], 64); err != nil {
		return nil
	}
	if out.Five, err = strconv.ParseFloat(f[1], 64); err != nil {
		return nil
	}
	if out.Fifteen, err = strconv.ParseFloat(f[2], 64); err != nil {
		return nil
	}
	return &out
}

// readMeminfo parses /proc/meminfo; nil anywhere the file does not exist.
func readMeminfo() *MemoryInfo {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil
	}
	return parseMeminfo(string(b))
}

func parseMeminfo(s string) *MemoryInfo {
	var m MemoryInfo
	for _, line := range strings.Split(s, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		kb, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		switch name {
		case "MemTotal":
			m.TotalBytes = kb * 1024
		case "MemAvailable":
			m.AvailableBytes = kb * 1024
		}
	}
	if m.TotalBytes == 0 {
		return nil
	}
	return &m
}

// diskSpace measures the volumes behind the database file and the recordings
// directory, folding them into one entry when they share a filesystem. A
// missing path (Postgres database, recordings in S3 with no local spool) is
// skipped rather than reported as zero.
func diskSpace(databasePath, recordingsPath string) []DiskSpace {
	type probe struct{ what, path string }
	probes := []probe{{"database", databasePath}, {"recordings", recordingsPath}}
	var out []DiskSpace
	seen := map[uint64]int{} // device id -> index in out
	var rootDev uint64
	if info, err := os.Stat("/"); err == nil {
		rootDev = deviceID(info)
	}
	for _, p := range probes {
		if p.path == "" {
			continue
		}
		info, err := os.Stat(p.path)
		if err != nil {
			continue
		}
		var st syscall.Statfs_t
		if err := syscall.Statfs(p.path, &st); err != nil {
			continue
		}
		dev := deviceID(info)
		if i, ok := seen[dev]; ok {
			out[i].What = out[i].What + " & " + p.what
			continue
		}
		seen[dev] = len(out)
		out = append(out, DiskSpace{
			What:       p.what,
			Path:       p.path,
			System:     dev == rootDev,
			TotalBytes: st.Blocks * uint64(st.Bsize), // #nosec G115 -- a block size, never negative
			FreeBytes:  st.Bavail * uint64(st.Bsize), // #nosec G115 -- a block size, never negative
		})
	}
	return out
}

func deviceID(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev) // #nosec G115 -- a device id, used as a map key only
	}
	return 0
}
