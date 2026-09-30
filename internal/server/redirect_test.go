// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRedirectHandler: the client's Host, without its port, selects a name
// the certificate covers (the certificate's spelling is used), the TLS port
// is added unless it is 443, the path and query travel, and a Host the
// certificate does not cover falls back to the listen host or is refused.
func TestRedirectHandler(t *testing.T) {
	covered := func() []string { return []string{"GW.example.test", "10.0.0.5", "::1"} }
	cases := []struct {
		tlsPort, fallback, host, path, want string
		status                              int
	}{
		{"443", "", "gw.example.test:80", "/login?next=%2Fadmin", "https://GW.example.test/login?next=%2Fadmin", 301},
		{"8443", "", "10.0.0.5", "/", "https://10.0.0.5:8443/", 301},
		{"443", "", "[::1]:80", "/x", "https://[::1]/x", 301},
		{"443", "10.0.0.5", "other.example.test", "/", "https://10.0.0.5/", 301},
		{"443", "10.0.0.5", "evil host<script>", "/", "https://10.0.0.5/", 301},
		{"443", "", "other.example.test", "/", "", 400},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", "http://placeholder"+c.path, nil)
		req.Host = c.host
		rr := httptest.NewRecorder()
		redirectHandler(c.tlsPort, c.fallback, covered).ServeHTTP(rr, req)
		if rr.Code != c.status || (c.status == 301 && rr.Header().Get("Location") != c.want) {
			t.Errorf("host %q port %s: %d %q (want %d %q)", c.host, c.tlsPort, rr.Code, rr.Header().Get("Location"), c.status, c.want)
		}
		if c.status == 301 && rr.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("host %q: redirect must not be cached", c.host)
		}
	}
	if srv := newRedirectServer(":80", "0.0.0.0:443", covered); srv.Handler == nil || srv.ReadHeaderTimeout == 0 {
		t.Fatal("redirect server must have a handler and a header timeout")
	}
}

// TestRedirectRefusalExplainsItself covers the case every cloud install hits:
// the browser asks for a public address that is translated upstream, so it is on
// no interface, is not in the self-signed certificate, and cannot be guessed.
// The refusal has to say which name was asked for and how to fix it, because
// "use https" taught nobody anything (manual QA).
func TestRedirectRefusalExplainsItself(t *testing.T) {
	// No fallback host: the listener is on every interface, as `zanskar init`
	// writes it, and the certificate covers the private address only.
	h := redirectHandler("443", "", func() []string { return []string{"10.0.0.7", "localhost"} })

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://203.0.113.9/login", nil)
	req.Host = "203.0.113.9"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"203.0.113.9", "ZANSKAR_TLS_HOSTS", "https://"} {
		if !strings.Contains(body, want) {
			t.Fatalf("refusal does not mention %q: %s", want, body)
		}
	}

	// A covered name still redirects, path and query intact.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://10.0.0.7/login?next=%2Fadmin", nil)
	req.Host = "10.0.0.7"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://10.0.0.7/login?next=%2Fadmin" {
		t.Fatalf("Location = %q", got)
	}
}
