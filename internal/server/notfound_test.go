// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// 2026-11-03 live audit, S1: every path answered 200 with the app, so
// /.git/HEAD, /metrics, /debug/pprof/ and the like read as exposed to every
// scanner. A console page still deep-links; anything else is not found.
func TestOnlyConsolePagesGetTheApp(t *testing.T) {
	h := spaHandler(testBundle)
	get := func(p string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, p, nil))
		return rr
	}
	for _, p := range []string{
		"/", "/login", "/login?error=x", "/home", "/connect?target=t1&protocol=ssh", "/access", "/sessions", "/activity",
		"/terminal", "/desktop", "/admin", "/admin/hosts", "/admin/hosts/abc", "/admin/no-such-page",
		"/audit", "/audit/recordings/r1",
	} {
		if rr := get(p); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "<title>Zanskar</title>") {
			t.Errorf("%s: %d, want the app", p, rr.Code)
		}
	}
	for _, p := range []string{
		"/.git/HEAD", "/.env", "/metrics", "/debug/pprof/", "/wp-login.php", "/.well-known/security.txt",
		"/adminx", "/administrator", "/server-status", "/x/../../etc/passwd",
	} {
		rr := get(p)
		if rr.Code != http.StatusNotFound || strings.Contains(rr.Body.String(), "<title>Zanskar</title>") {
			t.Errorf("%s: %d %q, want not found", p, rr.Code, rr.Body)
		}
	}
	// Bundle files are still served, at the root too.
	if rr := get("/logo-mark.svg"); rr.Code != http.StatusOK || rr.Body.String() != "<svg/>" {
		t.Errorf("a bundle file at the root: %d %q", rr.Code, rr.Body)
	}
}

// Every top-level page the console routes to is a console path here, or a
// reload of it would be not found: this reads the routes and the portals'
// links out of web/src/App.tsx.
func TestConsoleRootsMatchTheConsolesRoutes(t *testing.T) {
	src, err := os.ReadFile("../../web/src/App.tsx")
	if err != nil {
		t.Skipf("no console source here: %v", err)
	}
	re := regexp.MustCompile(`(?:path="|to: ')/([a-z-]*)`)
	seen := 0
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		seen++
		if !consoleRoots[m[1]] {
			t.Errorf("the console routes to /%s, which the gateway answers not found: add it to consoleRoots", m[1])
		}
	}
	if seen < 10 {
		t.Fatalf("read only %d routes from App.tsx; the pattern no longer matches it", seen)
	}
}

func TestRobotsKeepsCrawlersOut(t *testing.T) {
	rr := httptest.NewRecorder()
	spaHandler(testBundle).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/robots.txt", nil))
	if rr.Code != http.StatusOK || rr.Body.String() != "User-agent: *\nDisallow: /\n" || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("robots.txt: %d %q %q", rr.Code, rr.Header().Get("Content-Type"), rr.Body)
	}
}
