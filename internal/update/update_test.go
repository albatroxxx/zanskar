// SPDX-License-Identifier: Apache-2.0

package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		current, latest string
		want            bool
	}{
		{"1.4.0", "1.4.1", true},
		{"1.4.0", "1.5.0", true},
		{"1.4.0", "2.0.0", true},
		{"v1.4.0", "v1.4.0", false},
		{"1.4.1", "1.4.0", false},
		{"1.4.0-rc.1", "1.4.0", true},  // a release beats its own prerelease
		{"1.4.0", "1.5.0-rc.1", true},  // a newer prerelease still counts
		{"1.4.0", "1.4.0-rc.2", false}, // an older prerelease does not
		{"dev", "1.4.0", false},        // a development build is never behind
		{"1.4.0", "garbage", false},
		{"", "1.4.0", false},
	}
	for _, c := range cases {
		if got := Newer(c.current, c.latest); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.current, c.latest, got, c.want)
		}
	}
}

// TestCheck: a manifest with a newer version lights the bell with its notes
// link; an unreachable or broken manifest records the reason and never a
// version; a notes link that is not https is dropped, not shown.
func TestCheck(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest.json":
			_, _ = w.Write([]byte(`{"version":"1.5.0","notes_url":"https://example.test/releases/#v1-5-0","published_at":"2026-11-01"}`))
		case "/bad-link.json":
			_, _ = w.Write([]byte(`{"version":"1.5.0","notes_url":"javascript:alert(1)"}`))
		case "/broken.json":
			_, _ = w.Write([]byte(`{"version":`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &Checker{URL: srv.URL + "/latest.json", Current: "1.4.0"}
	s := c.Check(ctx)
	if !s.Newer || s.Latest != "1.5.0" || s.NotesURL != "https://example.test/releases/#v1-5-0" || s.Error != "" || s.CheckedAt == nil {
		t.Fatalf("newer: %+v", s)
	}
	if got := c.Status(); got.Latest != "1.5.0" || got.Current != "1.4.0" || !got.Enabled {
		t.Fatalf("status: %+v", got)
	}

	c = &Checker{URL: srv.URL + "/bad-link.json", Current: "1.4.0"}
	if s := c.Check(ctx); s.NotesURL != "" || !s.Newer {
		t.Fatalf("bad link: %+v", s)
	}

	c = &Checker{URL: srv.URL + "/broken.json", Current: "1.4.0"}
	if s := c.Check(ctx); s.Error == "" || s.Latest != "" || s.Newer {
		t.Fatalf("broken manifest: %+v", s)
	}

	c = &Checker{URL: srv.URL + "/missing.json", Current: "1.4.0"}
	if s := c.Check(ctx); s.Error == "" || s.Newer {
		t.Fatalf("missing manifest: %+v", s)
	}

	off := &Checker{URL: srv.URL + "/latest.json", Current: "1.4.0", Enabled: func() bool { return false }}
	if s := off.Status(); s.Enabled || s.Latest != "" {
		t.Fatalf("disabled before any check: %+v", s)
	}
}

// TestReadInstallState: the installer's report is read back as written, and
// a missing, empty or broken file reads as none.
func TestReadInstallState(t *testing.T) {
	dir := t.TempDir()
	if ReadInstallState(dir) != nil || ReadInstallState("") != nil {
		t.Fatal("state from nothing")
	}
	if err := os.WriteFile(filepath.Join(dir, StatusFile), []byte(`{"state":"failed","version":"1.5.0","message":"the release signature did not verify; nothing was installed","at":"2026-10-15T10:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	st := ReadInstallState(dir)
	if st == nil || st.State != "failed" || st.Version != "1.5.0" || st.Message == "" {
		t.Fatalf("state: %+v", st)
	}
	if err := os.WriteFile(filepath.Join(dir, StatusFile), []byte(`{"state":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if ReadInstallState(dir) != nil {
		t.Fatal("broken file read as a state")
	}
	if !IsVersion("1.5.0") || IsVersion("latest") {
		t.Fatal("IsVersion")
	}
}
