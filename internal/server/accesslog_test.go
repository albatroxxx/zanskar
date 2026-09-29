// SPDX-License-Identifier: Apache-2.0

package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

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

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
