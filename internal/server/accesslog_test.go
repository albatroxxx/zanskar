// SPDX-License-Identifier: Apache-2.0

package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"
	"testing/fstest"

	"github.com/albatroxxx/zanskar/internal/logring"
)

// TestAccessLogQuietPaths: polled routes are logged at debug so they do
// not fill the console's ring with their own traffic; everything else,
// and a failing poll, stays at info.
func TestAccessLogQuietPaths(t *testing.T) {
	ring := logring.New(50)
	level := new(slog.LevelVar)
	level.Set(slog.LevelInfo)
	s := &Server{log: slog.New(ring.Wrap(slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: level})))}
	ok := s.accessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	fail := s.accessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	for _, p := range []string{"/api/v1/admin/logs", "/healthz", "/api/v1/admin/system/status"} {
		ok.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", p, nil))
	}
	if n := len(ring.Snapshot(slog.LevelDebug, "", 50)); n != 0 {
		t.Fatalf("polled routes must not reach the ring at info, got %d", n)
	}
	ok.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/targets", nil))
	fail.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/readyz", nil))
	got := ring.Snapshot(slog.LevelDebug, "", 50)
	if len(got) != 2 || got[0].Attrs["path"] != "/readyz" || got[1].Attrs["path"] != "/api/v1/targets" {
		t.Fatalf("other requests and failing polls are logged: %+v", got)
	}
}

// TestAccessLogStaticFiles: a page load fetched about ten of the console's
// own files, each an info line (the live console, 2026-11-01). A served
// file of the bundle, and the theme script, are debug lines; the page
// itself, a path that is no file, and the API stay at info.
func TestAccessLogStaticFiles(t *testing.T) {
	ring := logring.New(50)
	level := new(slog.LevelVar)
	level.Set(slog.LevelInfo)
	s := &Server{log: slog.New(ring.Wrap(slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: level})))}
	bundle := fstest.MapFS{
		"index.html":           {Data: []byte("<!doctype html>")},
		"favicon.svg":          {Data: []byte("<svg/>")},
		"assets/index-abc.js":  {Data: []byte("console.log(1)")},
		"assets/index-abc.css": {Data: []byte("body{}")},
		"theme.js":             {Data: []byte("var t = " + themeMarker)},
	}
	mux := http.NewServeMux()
	mux.Handle("/", spaHandler(bundle))
	mux.Handle("GET /theme.js", themeScript(bundle, func() string { return "dark" }))
	mux.HandleFunc("GET /api/v1/targets", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	h := s.accessLog(mux)
	for _, p := range []string{"/assets/index-abc.js", "/assets/index-abc.css", "/favicon.svg", "/theme.js"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d", p, w.Code)
		}
	}
	if got := ring.Snapshot(slog.LevelDebug, "", 50); len(got) != 0 {
		t.Fatalf("the bundle's files must not reach the ring at info: %+v", got)
	}
	for _, p := range []string{"/admin/sessions", "/assets/gone.js", "/api/v1/targets"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", p, nil))
	}
	got := ring.Snapshot(slog.LevelDebug, "", 50)
	var paths []string
	for _, e := range got {
		paths = append(paths, e.Attrs["path"])
	}
	if len(paths) != 3 || !slices.Contains(paths, "/admin/sessions") || !slices.Contains(paths, "/assets/gone.js") || !slices.Contains(paths, "/api/v1/targets") {
		t.Fatalf("a page, a missing file and the API are logged at info: %v", paths)
	}
}

// TestAccessLogAddressOnlyOnFailure (2026-11-03 live audit, S4): a served
// request's line carries no client address, so the Logs page is not a trail
// of where each person went; a failed one keeps it, for a probe or a flood.
func TestAccessLogAddressOnlyOnFailure(t *testing.T) {
	ring := logring.New(50)
	level := new(slog.LevelVar)
	level.Set(slog.LevelInfo)
	s := &Server{log: slog.New(ring.Wrap(slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: level})))}
	for _, code := range []int{200, 302, 401, 404, 500} {
		h := s.accessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
		r := httptest.NewRequest("GET", "/api/v1/targets", nil)
		r.RemoteAddr = "198.51.100.7:4242"
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	got := ring.Snapshot(slog.LevelDebug, "", 50)
	if len(got) != 5 {
		t.Fatalf("lines: %d", len(got))
	}
	for _, e := range got {
		_, has := e.Attrs["remote"]
		failed := e.Attrs["status"] >= "400"
		if has != failed || (has && e.Attrs["remote"] != "198.51.100.7") {
			t.Fatalf("status %s: remote %q", e.Attrs["status"], e.Attrs["remote"])
		}
	}
}

// TestShellReadsAreQuiet (2026-11-05, live): every console page makes about
// eight reads of its own on opening, which filled the 2000-line ring and pushed
// the restart out of it within minutes. A served GET of one is at debug; a
// change to the same path, and a failure, stay at info, and a read of
// something a person asked for is still a line.
func TestShellReadsAreQuiet(t *testing.T) {
	ring := logring.New(50)
	level := new(slog.LevelVar)
	level.Set(slog.LevelDebug)
	s := &Server{log: slog.New(ring.Wrap(slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: level})))}
	for _, c := range []struct {
		method, path string
		status       int
		info         bool
	}{
		{"GET", "/api/v1/auth/me", 200, false},
		{"GET", "/api/v1/access-requests", 200, false},
		{"GET", "/api/v1/admin/system/update", 200, false},
		{"GET", "/api/v1/admin/system/host", 200, false},
		{"GET", "/api/v1/admin/system/metrics", 200, false},
		{"GET", "/api/v1/admin/cli", 200, false},
		{"GET", "/api/v1/admin/settings", 200, false}, // the Settings page's own reads
		{"GET", "/api/v1/admin/tls", 200, false},
		{"GET", "/api/v1/admin/overview", 200, false},
		{"GET", "/api/v1/me/targets", 200, false},
		{"GET", "/api/v1/me/sessions", 200, false},
		{"GET", "/api/v1/admin/settings", 500, true},   // a failed one is wanted
		{"PUT", "/api/v1/admin/settings", 200, true},   // so is a change
		{"GET", "/api/v1/auth/me", 401, true},          // a failure is wanted
		{"POST", "/api/v1/access-requests", 201, true}, // a change is wanted
		{"POST", "/api/v1/admin/system/update", 200, true},
		{"GET", "/api/v1/users", 200, true}, // what a person asked for
		{"GET", "/api/v1/audit/events", 200, true},
	} {
		h := s.accessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(c.status) }))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(c.method, c.path, nil))
	}
	info := map[string]bool{}
	for _, e := range ring.Snapshot(slog.LevelInfo, "", 50) {
		info[e.Attrs["method"]+" "+e.Attrs["path"]+" "+e.Attrs["status"]] = true
	}
	for _, c := range []struct {
		method, path string
		status       int
		info         bool
	}{
		{"GET", "/api/v1/auth/me", 200, false}, {"GET", "/api/v1/admin/cli", 200, false},
		{"GET", "/api/v1/auth/me", 401, true}, {"POST", "/api/v1/access-requests", 201, true},
		{"POST", "/api/v1/admin/system/update", 200, true}, {"GET", "/api/v1/users", 200, true},
		{"GET", "/api/v1/admin/settings", 200, false}, {"GET", "/api/v1/admin/tls", 200, false},
		{"GET", "/api/v1/admin/overview", 200, false}, {"GET", "/api/v1/me/targets", 200, false},
		{"GET", "/api/v1/admin/settings", 500, true}, {"PUT", "/api/v1/admin/settings", 200, true},
	} {
		key := c.method + " " + c.path + " " + strconv.Itoa(c.status)
		if info[key] != c.info {
			t.Errorf("%s at info = %v, want %v", key, info[key], c.info)
		}
	}
	if len(info) != 7 {
		t.Errorf("info lines: %v", info)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
