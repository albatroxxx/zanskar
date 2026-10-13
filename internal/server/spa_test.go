// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// TestSPAServesNoDirectoryListings: /assets/ and /fonts/ answered with an
// HTML index of every bundle file (L8). A directory is not a page: it gets
// the app like any other unknown path, never a listing.
func TestSPAServesNoDirectoryListings(t *testing.T) {
	h := spaHandler(fstest.MapFS{
		"index.html":           {Data: []byte("<title>Zanskar</title>")},
		"assets/app-1a2b.js":   {Data: []byte("console.log(1)")},
		"fonts/inter.woff2":    {Data: []byte("font")},
		"assets/deep/x-9f.css": {Data: []byte("body{}")},
	})
	for _, p := range []string{"/assets/", "/assets", "/fonts/", "/assets/deep/"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, p, nil))
		if body := rr.Body.String(); strings.Contains(body, "app-1a2b.js") || strings.Contains(body, "inter.woff2") || !strings.Contains(body, "<title>Zanskar</title>") {
			t.Errorf("%s: %d %q, want the app, not a listing", p, rr.Code, body)
		}
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/assets/app-1a2b.js", nil))
	if rr.Code != http.StatusOK || rr.Body.String() != "console.log(1)" {
		t.Errorf("a bundle file must still be served: %d %q", rr.Code, rr.Body)
	}
}

// TestCSPConnectsOnlyToItsOwnOrigin: connect-src listed ws: and wss:, which
// let a page open a WebSocket to any host at all, though the comment above
// it said connections stay on our origin (L5). 'self' covers our own
// WebSocket in every browser the bundle is built for.
func TestCSPConnectsOnlyToItsOwnOrigin(t *testing.T) {
	for _, d := range strings.Split(uiCSP, ";") {
		if d = strings.TrimSpace(d); strings.HasPrefix(d, "connect-src") && d != "connect-src 'self'" {
			t.Fatalf("got %q, want connect-src 'self'", d)
		}
	}
}
