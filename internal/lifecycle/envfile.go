// SPDX-License-Identifier: Apache-2.0

// Package lifecycle owns what happens to the running process as a whole:
// noticing that the environment file it was started from has changed since
// (so a restart is required for boot settings, ADR 0020), and restarting on
// an administrator's request after draining live sessions.
package lifecycle

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Prefix selects the variables the gateway reads.
const Prefix = "ZANSKAR_"

// SnapshotEnv returns the ZANSKAR_* variables of this process. serve calls
// it first thing so the snapshot is what the process actually started with.
func SnapshotEnv() map[string]string {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if ok && strings.HasPrefix(k, Prefix) {
			out[k] = v
		}
	}
	return out
}

// ParseEnvFile reads a file in the syntax systemd's EnvironmentFile= accepts:
// KEY=VALUE per line, blank lines and lines starting with # or ; ignored,
// surrounding double or single quotes stripped, a trailing backslash joins
// the next line. A leading "export " is tolerated for files also sourced by
// a shell. Only ZANSKAR_* keys are kept.
func ParseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator names the file in ZANSKAR_ENV_FILE
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var cont string
	for sc.Scan() {
		line := cont + sc.Text()
		cont = ""
		if strings.HasSuffix(line, "\\") {
			cont = strings.TrimSuffix(line, "\\")
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if !strings.HasPrefix(k, Prefix) {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// File states.
const (
	FileUnchanged  = "unchanged"  // the file matches what the process started with
	FileChanged    = "changed"    // a restart is required for the changes to apply
	FileMissing    = "missing"    // no file at the path (containers: the environment came from elsewhere)
	FileUnreadable = "unreadable" // the file exists but the service user may not read it
	FileNone       = "none"       // no path configured or found
)

// Report is what the console shows about the environment file. It names
// the variables that differ and never carries a value: the file holds the
// master key and the database credentials.
type Report struct {
	Path      string     `json:"path,omitempty"`
	State     string     `json:"state"`
	Changed   []string   `json:"changed,omitempty"`
	Error     string     `json:"error,omitempty"`
	ModTime   *time.Time `json:"mod_time,omitempty"`
	CheckedAt time.Time  `json:"checked_at"`
}

// RestartRequired reports whether the file differs from the running process.
func (r Report) RestartRequired() bool { return r.State == FileChanged }

// Drift compares the environment file with the process's start-up snapshot.
type Drift struct {
	Path    string
	Started map[string]string

	mu      sync.Mutex
	cached  Report
	modTime time.Time
	size    int64
}

// Check reads the file when it changed on disk since the last check and
// returns the report. It is cheap enough to serve on every status poll.
func (d *Drift) Check() Report {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now().UTC()
	if d.Path == "" {
		return Report{State: FileNone, CheckedAt: now}
	}
	info, err := os.Stat(d.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		d.cached = Report{}
		return Report{Path: d.Path, State: FileMissing, CheckedAt: now}
	case err != nil:
		d.cached = Report{}
		return Report{Path: d.Path, State: FileUnreadable, Error: err.Error(), CheckedAt: now}
	}
	if d.cached.State != "" && info.ModTime().Equal(d.modTime) && info.Size() == d.size {
		r := d.cached
		r.CheckedAt = now
		return r
	}
	file, err := ParseEnvFile(d.Path)
	mod := info.ModTime().UTC()
	if err != nil {
		state := FileUnreadable
		if errors.Is(err, fs.ErrPermission) {
			err = errors.New("the service user cannot read the file; make it readable by the zanskar group (chgrp zanskar, chmod 0640)")
		}
		d.cached = Report{}
		return Report{Path: d.Path, State: state, Error: err.Error(), ModTime: &mod, CheckedAt: now}
	}
	changed := Diff(d.Started, file)
	r := Report{Path: d.Path, State: FileUnchanged, Changed: changed, ModTime: &mod, CheckedAt: now}
	if len(changed) > 0 {
		r.State = FileChanged
	}
	d.cached, d.modTime, d.size = r, info.ModTime(), info.Size()
	return r
}

// Diff returns, sorted, the names of the variables whose value differs
// between the process's start-up environment and the file, including ones
// present on one side only. Names only, never values.
func Diff(started, file map[string]string) []string {
	var out []string
	for k, v := range file {
		if sv, ok := started[k]; !ok || sv != v {
			out = append(out, k)
		}
	}
	for k := range started {
		if _, ok := file[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
