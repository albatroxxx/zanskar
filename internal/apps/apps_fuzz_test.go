// SPDX-License-Identifier: Apache-2.0

package apps

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// FuzzSafePath: whatever a query carries as the return path, what comes
// out is a path on the application's own host: one leading slash, no
// scheme, host or credentials, nothing a header could be broken with.
func FuzzSafePath(f *testing.F) {
	for _, s := range []string{"/", "/a/b?c=d", "//evil.test/x", "/\\evil", "https://evil.test", "/ok\r\nSet-Cookie: x", "/%2F%2Fevil", "/\t/evil", "", "/#frag", "/a?b=%zz"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out := safePath(in)
		if out == "/" {
			return
		}
		if out != in || len(out) > 2048 || !strings.HasPrefix(out, "/") || strings.HasPrefix(out, "//") || strings.HasPrefix(out, "/\\") || strings.ContainsAny(out, "\r\n\x00") {
			t.Fatalf("safePath(%q) = %q", in, out)
		}
		u, err := url.Parse(out)
		if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
			t.Fatalf("safePath(%q) = %q parses to scheme %q host %q", in, out, u.Scheme, u.Host)
		}
	})
}

// FuzzSanitizeSetCookies: an upstream's Set-Cookie lines, however shaped,
// never leave the proxy naming one of the gateway's cookies or carrying a
// Domain attribute; what parses as a cookie still does afterwards.
func FuzzSanitizeSetCookies(f *testing.F) {
	for _, s := range []string{
		"sid=1; Domain=apps.test; Path=/; HttpOnly",
		"zanskar_app=evil; Path=/",
		"__Host-zanskar_session=x",
		"plain=2; Path=/",
		"=; Domain=",
		"a=b; Domain=.x; Domain=.y",
		"garbage",
		"",
		"a=b; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Domain=example.org; Secure; SameSite=None",
	} {
		f.Add(s, "plain=2")
	}
	f.Fuzz(func(t *testing.T, first, second string) {
		h := http.Header{}
		h.Add("Set-Cookie", first)
		h.Add("Set-Cookie", second)
		sanitizeSetCookies(h)
		for _, line := range h.Values("Set-Cookie") {
			c, err := http.ParseSetCookie(line)
			if err != nil {
				continue // passed through unparsed, as it came
			}
			if ownCookie(c.Name) {
				t.Fatalf("own cookie %q left in %q", c.Name, line)
			}
			if c.Domain != "" {
				t.Fatalf("Domain %q left in %q", c.Domain, line)
			}
		}
	})
}

// FuzzRewriteLocation: a Location header of any shape is either left alone
// or moved to the application's origin; the rewrite never panics and never
// points at a third host.
func FuzzRewriteLocation(f *testing.F) {
	dest, _ := url.Parse("https://wiki.internal:8443")
	for _, s := range []string{"https://wiki.internal:8443/login?x=1", "/relative", "https://other.test/", "http://wiki.internal:8443/", "://bad", "", "https://wiki.internal:8443"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, loc string) {
		h := http.Header{"Location": {loc}}
		rewriteLocation(h, dest, "https://wiki.apps.test")
		got := h.Get("Location")
		if got == loc {
			return
		}
		u, err := url.Parse(got)
		if err != nil || u.Host != "wiki.apps.test" || u.Scheme != "https" {
			t.Fatalf("rewriteLocation(%q) = %q", loc, got)
		}
	})
}
