// SPDX-License-Identifier: Apache-2.0

// Package update tells an administrator when a newer Zanskar exists (ADR
// 0032). Once a day the gateway fetches a small manifest from the project
// site — a version and a release-notes link, nothing about this gateway is
// sent — and the console's bell lights when it is newer than the running
// build. Installing is the update unit's job, not this package's.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultURL is where releases publish the manifest.
const DefaultURL = "https://albatroxxx.github.io/zanskar/releases/latest.json"

const (
	defaultEvery      = 24 * time.Hour
	defaultFirstAfter = 30 * time.Second
	fetchTimeout      = 10 * time.Second
	manifestLimit     = 64 << 10
)

// Manifest is the published file.
type Manifest struct {
	Version     string `json:"version"`
	NotesURL    string `json:"notes_url"`
	PublishedAt string `json:"published_at,omitempty"`
}

// Status is what the bell shows.
type Status struct {
	Current     string     `json:"current"`
	Latest      string     `json:"latest,omitempty"`
	NotesURL    string     `json:"notes_url,omitempty"`
	PublishedAt string     `json:"published_at,omitempty"`
	Newer       bool       `json:"newer"`
	CheckedAt   *time.Time `json:"checked_at,omitempty"`
	Error       string     `json:"error,omitempty"`
	// Enabled mirrors the runtime setting; off, the bell only says so.
	Enabled bool `json:"enabled"`
	// Installable says the console can ask for the install: a systemd host
	// with a state directory for the request (ADR 0032).
	Installable bool `json:"installable"`
	// Install is the installer's last report, when there is one.
	Install *InstallState `json:"install,omitempty"`
}

// Checker fetches the manifest on a schedule and keeps the last answer.
type Checker struct {
	URL     string
	Current string
	// Enabled is read before every scheduled check, so the runtime setting
	// applies live; nil means enabled.
	Enabled    func() bool
	Client     *http.Client
	Log        *slog.Logger
	Every      time.Duration
	FirstAfter time.Duration

	mu   sync.Mutex
	last Status
}

func (c *Checker) enabled() bool { return c.Enabled == nil || c.Enabled() }

// Run checks shortly after start and then every Every, while ctx lives.
func (c *Checker) Run(ctx context.Context) {
	first, every := c.FirstAfter, c.Every
	if first <= 0 {
		first = defaultFirstAfter
	}
	if every <= 0 {
		every = defaultEvery
	}
	wait := first
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if c.enabled() {
			c.Check(ctx)
		}
		wait = every
	}
}

// Status returns the last answer, with the current version and the
// setting's present value.
func (c *Checker) Status() Status {
	c.mu.Lock()
	s := c.last
	c.mu.Unlock()
	s.Current, s.Enabled = c.Current, c.enabled()
	return s
}

// Check fetches the manifest now and records the answer.
func (c *Checker) Check(ctx context.Context) Status {
	now := time.Now().UTC()
	s := Status{Current: c.Current, Enabled: c.enabled(), CheckedAt: &now}
	m, err := c.fetch(ctx)
	switch {
	case err != nil:
		s.Error = err.Error()
		if c.Log != nil {
			c.Log.Info("version check failed", "err", err)
		}
	default:
		s.Latest, s.NotesURL, s.PublishedAt = m.Version, m.NotesURL, m.PublishedAt
		s.Newer = Newer(c.Current, m.Version)
	}
	c.mu.Lock()
	c.last = s
	c.mu.Unlock()
	return s
}

func (c *Checker) fetch(ctx context.Context) (Manifest, error) {
	url := c.URL
	if url == "" {
		url = DefaultURL
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: fetchTimeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Manifest{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "zanskar/"+c.Current)
	resp, err := client.Do(req)
	if err != nil {
		return Manifest{}, fmt.Errorf("could not reach the project site: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Manifest{}, fmt.Errorf("the project site answered %s", resp.Status)
	}
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, manifestLimit)).Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("the manifest is not valid JSON: %w", err)
	}
	if _, ok := parse(m.Version); !ok {
		return Manifest{}, errors.New("the manifest carries no version")
	}
	// The link is shown in the console: only an https page, never a scheme
	// that would run in the browser.
	if m.NotesURL != "" && !strings.HasPrefix(m.NotesURL, "https://") {
		m.NotesURL = ""
	}
	return m, nil
}

// IsVersion reports whether s is a version this package understands.
func IsVersion(s string) bool {
	_, ok := parse(s)
	return ok
}

// StatusFile is what the package's installer writes under the state dir
// as it works (ADR 0032); the bell reads it back.
const StatusFile = "update-status.json"

// InstallState is one line from the installer: where it got to.
type InstallState struct {
	State   string `json:"state"` // running | done | failed
	Version string `json:"version"`
	Message string `json:"message"`
	At      string `json:"at"`
}

// ReadInstallState returns the installer's last report, or nil when there
// is none or it cannot be read.
func ReadInstallState(stateDir string) *InstallState {
	if stateDir == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(stateDir, StatusFile)) // #nosec G304 -- a fixed file name under the configured state directory
	if err != nil {
		return nil
	}
	var st InstallState
	if err := json.Unmarshal(b, &st); err != nil || st.State == "" {
		return nil
	}
	return &st
}

// Newer reports whether latest is a later release than current. A current
// that is not a version (a "dev" build) is never behind, so a development
// gateway stays quiet.
func Newer(current, latest string) bool {
	cv, ok := parse(current)
	if !ok {
		return false
	}
	lv, ok := parse(latest)
	if !ok {
		return false
	}
	return compare(lv, cv) > 0
}

type version struct {
	nums [3]int
	pre  string
}

// parse reads v?MAJOR.MINOR.PATCH with an optional -prerelease.
func parse(s string) (version, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	core, pre, _ := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return version{}, false
	}
	var v version
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return version{}, false
		}
		v.nums[i] = n
	}
	v.pre = pre
	return v, true
}

// compare orders versions: by number, then a release above any prerelease
// of the same number, then prereleases by text.
func compare(a, b version) int {
	for i := range a.nums {
		if a.nums[i] != b.nums[i] {
			if a.nums[i] > b.nums[i] {
				return 1
			}
			return -1
		}
	}
	switch {
	case a.pre == b.pre:
		return 0
	case a.pre == "":
		return 1
	case b.pre == "":
		return -1
	default:
		return strings.Compare(a.pre, b.pre)
	}
}
