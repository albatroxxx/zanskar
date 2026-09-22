// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
)

func newTestServer(t *testing.T, migrate bool) *Server {
	t.Helper()
	db, err := store.Open(context.Background(), config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if migrate {
		if _, err := store.Migrate(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{ListenAddr: "127.0.0.1:0"}
	return New(cfg, db, slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{})
}

func TestHealthAndHeaders(t *testing.T) {
	s := newTestServer(t, true)
	rr := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("healthz: %d", rr.Code)
	}
	for _, h := range []string{"X-Content-Type-Options", "Content-Security-Policy", "X-Request-Id", "Cache-Control"} {
		if rr.Header().Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}
	if rr.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must not be sent on a plain HTTP listener")
	}
}

func TestReadyzReportsPendingMigrations(t *testing.T) {
	s := newTestServer(t, false)
	rr := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 before migrations, got %d", rr.Code)
	}
	s = newTestServer(t, true)
	rr = httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 after migrations, got %d: %s", rr.Code, rr.Body)
	}
}

func TestNotFoundIsJSONWithRequestID(t *testing.T) {
	s := newTestServer(t, true)
	rr := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/nope", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("got %d", rr.Code)
	}
	var e apiError
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil || e.RequestID == "" || e.Code != "not_found" {
		t.Fatalf("bad error body: %s (%v)", rr.Body, err)
	}
}

func TestClientRequestIDIgnored(t *testing.T) {
	s := newTestServer(t, true)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-Id", "forged")
	s.http.Handler.ServeHTTP(rr, req)
	if rr.Header().Get("X-Request-Id") == "forged" {
		t.Fatal("client-supplied request id must not be echoed")
	}
}

func TestSPAFallbackAndCSP(t *testing.T) {
	s := newTestServer(t, true)
	for _, p := range []string{"/", "/admin/targets", "/login"} {
		rr := httptest.NewRecorder()
		s.http.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, p, nil))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "<title>Zanskar</title>") {
			t.Fatalf("%s: %d %q", p, rr.Code, rr.Body.String()[:40])
		}
		csp := rr.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'self'") {
			t.Fatalf("%s: ui csp missing: %q", p, csp)
		}
		// The recording player's WebAssembly terminal emulator needs this, or
		// playback is blank. It allows WASM, not JavaScript eval.
		if !strings.Contains(csp, "'wasm-unsafe-eval'") {
			t.Fatalf("%s: ui csp must allow wasm: %q", p, csp)
		}
	}
	rr := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/version", nil))
	if csp := rr.Header().Get("Content-Security-Policy"); !strings.HasPrefix(csp, "default-src 'none'; frame-ancestors") {
		t.Fatalf("api csp: %q", csp)
	}
}
