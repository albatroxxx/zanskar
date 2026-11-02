// SPDX-License-Identifier: Apache-2.0

package browsergw

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"slices"
	"testing"
)

func decodePolicy(t *testing.T, s Spec) map[string]any {
	t.Helper()
	raw, err := policyJSON(s, "172.30.0.2")
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("policy is not JSON: %v", err)
	}
	return p
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// TestPolicyJSON (ADR 0034, ADR 0037 and its amendment of 2026-11-02): the
// browser goes to the relay's SOCKS proxy for everything, loopback
// included; it may open exactly the application's origins, each by scheme,
// host (not its subdomains) and port; the upstream is the start, home and
// new-tab page; Chromium's own pages, files, javascript:, view-source:,
// prediction and WebRTC outside the proxy stay shut.
func TestPolicyJSON(t *testing.T) {
	s := spec(t)
	p := decodePolicy(t, s)
	proxy := p["ProxySettings"].(map[string]any)
	if proxy["ProxyMode"] != "fixed_servers" || proxy["ProxyServer"] != "socks5://172.30.0.2:1080" || proxy["ProxyBypassList"] != "<-loopback>" {
		t.Fatalf("proxy: %v", proxy)
	}
	if got := strs(p["URLAllowlist"]); fmt.Sprint(got) != "[http://.wiki.internal:8080]" {
		t.Fatalf("allowlist: %v", got)
	}
	block := strs(p["URLBlocklist"])
	for _, want := range []string{"*", "chrome://*", "chrome-untrusted://*", "file://*", "javascript:*", "view-source:*", "devtools://*"} {
		if !slices.Contains(block, want) {
			t.Errorf("blocklist misses %s: %v", want, block)
		}
	}
	for k, want := range map[string]any{
		"HomepageLocation": "http://wiki.internal:8080/", "NewTabPageLocation": "http://wiki.internal:8080/",
		"DeveloperToolsAvailability": float64(2), "DownloadRestrictions": float64(3), "PrintingEnabled": false,
		"NetworkPredictionOptions": float64(2), "WebRtcIPHandlingPolicy": "disable_non_proxied_udp",
		"BookmarkBarEnabled": false, "PasswordManagerEnabled": false, "SyncDisabled": true,
		"CommandLineFlagSecurityWarningsEnabled": false,
	} {
		if p[k] != want {
			t.Errorf("%s = %v, want %v", k, p[k], want)
		}
	}
	if fmt.Sprint(strs(p["RestoreOnStartupURLs"])) != "[http://wiki.internal:8080/]" {
		t.Errorf("start page: %v", p["RestoreOnStartupURLs"])
	}
	if _, ok := p["ManagedBookmarks"]; ok {
		t.Errorf("an application with one origin gets no bookmarks: %v", p["ManagedBookmarks"])
	}
}

// TestPolicyJSONWithEndpoints: further origins join the allowlist exactly
// (an IP literal as written, IPv6 in brackets) and appear, after the
// upstream, in one bookmarks folder named after the application, shown on
// the bar; developer tools open when the grant allows them.
func TestPolicyJSONWithEndpoints(t *testing.T) {
	s := spec(t)
	parse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	s.Endpoints = []Endpoint{
		{Name: "API", URL: parse("https://api.internal"), IP: net.ParseIP("10.0.0.51")},
		{Name: "Metrics", URL: parse("http://10.0.0.9:3000"), IP: net.ParseIP("10.0.0.9")},
		{Name: "v6", URL: parse("https://[fd00::9]:8443"), IP: net.ParseIP("fd00::9")},
	}
	s.DevTools = true
	p := decodePolicy(t, s)
	want := "[http://.wiki.internal:8080 https://.api.internal:443 http://10.0.0.9:3000 https://[fd00::9]:8443 devtools://*]"
	if got := strs(p["URLAllowlist"]); fmt.Sprint(got) != want {
		t.Fatalf("allowlist: %v\nwant %s", got, want)
	}
	if slices.Contains(strs(p["URLBlocklist"]), "devtools://*") || p["DeveloperToolsAvailability"] != float64(1) {
		t.Fatalf("developer tools by grant: %v %v", p["URLBlocklist"], p["DeveloperToolsAvailability"])
	}
	if p["BookmarkBarEnabled"] != true {
		t.Fatalf("the bar shows the folder: %v", p["BookmarkBarEnabled"])
	}
	raw, _ := json.Marshal(p["ManagedBookmarks"])
	wantMarks := `[{"toplevel_name":"Wiki"},{"name":"Wiki","url":"http://wiki.internal:8080/"},{"name":"API","url":"https://api.internal/"},` +
		`{"name":"Metrics","url":"http://10.0.0.9:3000/"},{"name":"v6","url":"https://[fd00::9]:8443/"}]`
	if string(raw) != wantMarks {
		t.Fatalf("bookmarks:\n%s\nwant\n%s", raw, wantMarks)
	}
}

// TestResolverRules: the upstream's name maps to the relay (for a browser
// image from before the proxy), the relay's address is kept from the
// catch-all so the proxy can be reached at all, and every other name maps
// to nothing.
func TestResolverRules(t *testing.T) {
	if got := resolverRules(spec(t), "172.30.0.2"); got != "MAP wiki.internal 172.30.0.2, EXCLUDE 172.30.0.2, MAP * ~NOTFOUND" {
		t.Fatalf("rules: %s", got)
	}
}
