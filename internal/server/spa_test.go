// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

var testBundle = fstest.MapFS{
	"index.html":           {Data: []byte("<title>Zanskar</title>")},
	"assets/app-1a2b.js":   {Data: []byte("console.log(1)")},
	"fonts/inter.woff2":    {Data: []byte("font")},
	"assets/deep/x-9f.css": {Data: []byte("body{}")},
	"logo-mark.svg":        {Data: []byte("<svg/>")},
}

// TestSPAServesNoDirectoryListings: /assets/ and /fonts/ answered with an
// HTML index of every bundle file (L8). A directory is not a page: since
// 1.15.0 it is not found, like any path outside the console, never a listing.
func TestSPAServesNoDirectoryListings(t *testing.T) {
	h := spaHandler(testBundle)
	for _, p := range []string{"/assets/", "/assets", "/fonts/", "/assets/deep/"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, p, nil))
		if body := rr.Body.String(); strings.Contains(body, "app-1a2b.js") || strings.Contains(body, "inter.woff2") || rr.Code != http.StatusNotFound {
			t.Errorf("%s: %d %q, want not found, never a listing", p, rr.Code, body)
		}
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/assets/app-1a2b.js", nil))
	if rr.Code != http.StatusOK || rr.Body.String() != "console.log(1)" {
		t.Errorf("a bundle file must still be served: %d %q", rr.Code, rr.Body)
	}
}

// TestCSPInlineIsForStylesOnly (2026-11-03 live audit, S3): style-src keeps
// 'unsafe-inline' because xterm's renderer writes each cell's colours as a
// style attribute and sizes its viewport with a <style> element; without it
// every terminal and recording renders unstyled. Nothing else may be inline:
// scripts come from our origin alone (no 'unsafe-inline', no 'unsafe-eval'),
// so a CSS injection still needs an HTML injection, which React escapes.
func TestCSPInlineIsForStylesOnly(t *testing.T) {
	dirs := map[string]string{}
	for d := range strings.SplitSeq(uiCSP, ";") {
		d = strings.TrimSpace(d)
		name, rest, _ := strings.Cut(d, " ")
		dirs[name] = rest
	}
	if dirs["script-src"] != "'self' 'wasm-unsafe-eval'" {
		t.Fatalf("script-src %q: our origin and WebAssembly only", dirs["script-src"])
	}
	if dirs["style-src"] != "'self' 'unsafe-inline'" {
		t.Fatalf("style-src %q", dirs["style-src"])
	}
	for name, v := range dirs {
		if name != "style-src" && (strings.Contains(v, "'unsafe-inline'") || strings.Contains(v, "'unsafe-eval'")) {
			t.Fatalf("%s %q allows inline or eval", name, v)
		}
	}
	if dirs["default-src"] != "'none'" || dirs["object-src"] != "" && dirs["object-src"] != "'none'" {
		t.Fatalf("default-src %q", dirs["default-src"])
	}
}

// TestCSPConnectsOnlyToItsOwnOrigin: connect-src listed ws: and wss:, which
// let a page open a WebSocket to any host at all, though the comment above
// it said connections stay on our origin (L5). 'self' covers our own
// WebSocket in every browser the bundle is built for.
func TestCSPConnectsOnlyToItsOwnOrigin(t *testing.T) {
	for d := range strings.SplitSeq(uiCSP, ";") {
		if d = strings.TrimSpace(d); strings.HasPrefix(d, "connect-src") && d != "connect-src 'self'" {
			t.Fatalf("got %q, want connect-src 'self'", d)
		}
	}
}
