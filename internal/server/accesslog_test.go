// SPDX-License-Identifier: Apache-2.0

package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
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

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
