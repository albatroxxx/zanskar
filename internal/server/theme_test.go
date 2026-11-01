// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

// TestThemeScriptWritesTheConsoleTheme: the theme set for everyone in
// Settings (display.theme) reaches every page before its first paint, from
// the bundle's own script; anything but the three themes is written as
// system, and nothing caches the answer past a change.
func TestThemeScriptWritesTheConsoleTheme(t *testing.T) {
	// The real script, so an edit that drops the marker fails here rather
	// than turning the setting off with every other test passing.
	src, err := os.ReadFile("../../web/public/theme.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), themeMarker) {
		t.Fatalf("web/public/theme.js has no %s for the gateway to write over", themeMarker)
	}
	theme := "dark"
	h := themeScript(fstest.MapFS{"theme.js": {Data: src}}, func() string { return theme })
	for _, tc := range []struct{ stored, want string }{
		{"dark", `'dark' /* zanskar:theme */`},
		{"light", `'light' /* zanskar:theme */`},
		{"system", `'system' /* zanskar:theme */`},
		{"'; alert(1); '", `'system' /* zanskar:theme */`},
	} {
		theme = tc.stored
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/theme.js", nil))
		body := rr.Body.String()
		if rr.Code != http.StatusOK || !strings.Contains(body, tc.want) || strings.Contains(body, "alert") {
			t.Errorf("%q: %d, want %s in\n%s", tc.stored, rr.Code, tc.want, body)
		}
		if ct := rr.Header().Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
			t.Errorf("Content-Type %q: nosniff refuses a script that is not JavaScript", ct)
		}
		if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control %q, want no-store", cc)
		}
	}
	if themeScript(fstest.MapFS{"index.html": {Data: []byte("x")}}, func() string { return "dark" }) != nil {
		t.Error("a bundle without the script must leave /theme.js to the bundle handler")
	}
}

// TestThemeScriptCarriesTheConsoleHeaders: the script is answered with the
// console's security headers, like the bundle's own files.
func TestThemeScriptCarriesTheConsoleHeaders(t *testing.T) {
	s := newTestServer(t, false)
	h := themeScript(fstest.MapFS{"theme.js": {Data: []byte("var g = " + themeMarker)}}, func() string { return "light" })
	mux := http.NewServeMux()
	mux.Handle("GET /theme.js", h)
	rr := httptest.NewRecorder()
	s.securityHeaders(mux).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/theme.js", nil))
	if !strings.Contains(rr.Body.String(), `'light'`) || rr.Header().Get("X-Content-Type-Options") != "nosniff" || rr.Header().Get("Content-Security-Policy") != uiCSP {
		t.Fatalf("got %d %q, headers %v", rr.Code, rr.Body, rr.Header())
	}
}
