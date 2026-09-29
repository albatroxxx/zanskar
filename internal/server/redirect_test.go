// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http/httptest"
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
