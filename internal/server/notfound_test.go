// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
		"/", "/login", "/login?error=x", "/home", "/connect?target=t1&protocol=ssh", "/access", "/sessions",
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

func TestRobotsKeepsCrawlersOut(t *testing.T) {
	rr := httptest.NewRecorder()
	spaHandler(testBundle).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/robots.txt", nil))
	if rr.Code != http.StatusOK || rr.Body.String() != "User-agent: *\nDisallow: /\n" || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("robots.txt: %d %q %q", rr.Code, rr.Header().Get("Content-Type"), rr.Body)
	}
}

// security.txt names the operator's contact only once they have set one; the
// project's address never goes into every gateway.
func TestSecurityTxtOnlyWithAContact(t *testing.T) {
	contact := ""
	h := securityTxt(func() string { return contact }, "https://gw.example.com/")
	get := func() *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil))
		return rr
	}
	if rr := get(); rr.Code != http.StatusNotFound {
		t.Fatalf("no contact: %d, want not found", rr.Code)
	}
	contact = "mailto:security@example.com"
	rr := get()
	body := rr.Body.String()
	if rr.Code != http.StatusOK || !strings.HasPrefix(body, "Contact: mailto:security@example.com\nExpires: ") ||
		!strings.Contains(body, "\nCanonical: https://gw.example.com/.well-known/security.txt\n") {
		t.Fatalf("security.txt: %d %q", rr.Code, body)
	}
	line := strings.Split(body, "\n")[1]
	exp, err := time.Parse(time.RFC3339, strings.TrimPrefix(line, "Expires: "))
	if err != nil || time.Until(exp) < 80*24*time.Hour || time.Until(exp) > 366*24*time.Hour {
		t.Fatalf("Expires %q (%v): RFC 9116 wants it ahead and under a year", line, err)
	}
}
