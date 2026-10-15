// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/store"
)

// stubApps serves one application host and records what reached it.
type stubApps struct{ saw *http.Request }

func (a *stubApps) Serves(host string) bool { return strings.EqualFold(host, "wiki.apps.test") }

func (a *stubApps) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.saw = r
	_, _ = io.WriteString(w, "app")
}

// TestDispatchByHost: a request for an application host (ADR 0033) reaches
// the applications handler with the request id and the client address, and
// without the console's security headers; every other host is the console,
// headers and all. The redirect listener covers a wildcard name.
func TestDispatchByHost(t *testing.T) {
	db, err := store.Open(context.Background(), config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	apps := &stubApps{}
	s := New(&config.Config{ListenAddr: "127.0.0.1:0"}, db, slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{Apps: apps})

	req := httptest.NewRequest(http.MethodGet, "http://wiki.apps.test/healthz", nil)
	rr := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "app" || apps.saw == nil {
		t.Fatalf("application host: %d %q", rr.Code, rr.Body)
	}
	if rr.Header().Get("X-Request-Id") == "" || httpx.RequestID(apps.saw.Context()) == "" {
		t.Error("the request id must reach an application request")
	}
	if rr.Header().Get("Content-Security-Policy") != "" || rr.Header().Get("X-Frame-Options") != "" {
		t.Errorf("console headers on an application response: %v", rr.Header())
	}

	rr = httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://gw.test/healthz", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"ok"`) || rr.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("console host: %d %q %v", rr.Code, rr.Body, rr.Header())
	}

	covered := func() []string { return []string{"gw.example.test", "*.apps.example.test"} }
	for host, want := range map[string]string{
		"wiki.apps.example.test": "https://wiki.apps.example.test/x",
		"a.b.apps.example.test":  "",
		"apps.example.test":      "",
	} {
		req := httptest.NewRequest(http.MethodGet, "http://placeholder/x", nil)
		req.Host = host
		rr := httptest.NewRecorder()
		redirectHandler("443", "", covered).ServeHTTP(rr, req)
		if got := rr.Header().Get("Location"); got != want {
			t.Errorf("redirect for %q: %q, want %q", host, got, want)
		}
	}
}
