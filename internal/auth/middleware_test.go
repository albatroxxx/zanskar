// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// TestRealIPTrustBoundary pins the rule that decides which address the audit
// log records: a forwarded address counts only when the peer is a trusted
// proxy, and a client cannot talk its way past that by forging header entries.
func TestRealIPTrustBoundary(t *testing.T) {
	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	privateToo := append([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, loopback...)

	cases := []struct {
		name    string
		peer    string
		xff     []string
		trusted []netip.Prefix
		want    string
	}{
		{"no trusted proxies ignores the header", "127.0.0.1:5000", []string{"203.0.113.9"}, nil, "127.0.0.1"},
		{"untrusted peer cannot forge an address", "198.51.100.7:5000", []string{"203.0.113.9"}, loopback, "198.51.100.7"},
		{"trusted proxy supplies the client", "127.0.0.1:5000", []string{"203.0.113.9"}, loopback, "203.0.113.9"},
		{"forged entries left of the real one are ignored", "127.0.0.1:5000", []string{"1.2.3.4, 203.0.113.9"}, loopback, "203.0.113.9"},
		{"trusted hops are skipped right to left", "127.0.0.1:5000", []string{"203.0.113.9, 10.0.0.2"}, privateToo, "203.0.113.9"},
		{"header split across repeated fields", "127.0.0.1:5000", []string{"1.2.3.4", "203.0.113.9"}, loopback, "203.0.113.9"},
		{"all hops trusted falls back to the peer", "127.0.0.1:5000", []string{"10.0.0.2"}, privateToo, "127.0.0.1"},
		{"garbage entries do not break the walk", "127.0.0.1:5000", []string{"not-an-ip, 203.0.113.9"}, loopback, "203.0.113.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			h := RealIP(tc.trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = ClientIP(r)
			}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.peer
			for _, v := range tc.xff {
				req.Header.Add("X-Forwarded-For", v)
			}
			h.ServeHTTP(httptest.NewRecorder(), req)
			if got != tc.want {
				t.Fatalf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestClientIPWithoutMiddleware keeps the direct-connection path working.
func TestClientIPWithoutMiddleware(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.7:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := ClientIP(req); got != "198.51.100.7" {
		t.Fatalf("ClientIP = %q, want the peer address", got)
	}
}
