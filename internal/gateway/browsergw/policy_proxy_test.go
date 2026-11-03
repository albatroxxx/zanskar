// SPDX-License-Identifier: Apache-2.0

package browsergw

import (
	"encoding/json"
	"net/url"
	"testing"
)

// TestPolicyUnderPublicDependencies (ADR 0037, amended 2026-11-03, later):
// the browser's proxy is the relay's inspecting HTTP proxy, Chromium's
// catch-all block and the origin allowlist go (the relay keeps a page to the
// origins; the catch-all blocked frames), the scheme blocks stay, and
// developer tools are allowed only when granted. Held to its origins, the
// policy is as it was: SOCKS, the catch-all and the allowlist.
func TestPolicyUnderPublicDependencies(t *testing.T) {
	s := spec(t)
	s.PublicDependencies = true
	s.Endpoints = []Endpoint{{Name: "API", URL: mustURL(t, "https://api.internal:8443"), IP: nil}}
	p := policyOf(t, s)
	ps := p["ProxySettings"].(map[string]any)
	if ps["ProxyServer"] != "http://172.30.0.2:3128" || ps["ProxyBypassList"] != "<-loopback>" {
		t.Errorf("proxy settings: %v", ps)
	}
	block := strs(p["URLBlocklist"])
	for _, b := range block {
		if b == "*" {
			t.Errorf("the catch-all block stayed: %v", block)
		}
	}
	for _, want := range []string{"chrome://*", "file://*", "javascript:*", "view-source:*", "devtools://*"} {
		if !contains(block, want) {
			t.Errorf("block misses %s: %v", want, block)
		}
	}
	if v, ok := p["URLAllowlist"]; ok {
		t.Errorf("an allowlist under public dependencies: %v", v)
	}
	s.DevTools = true
	if got := strs(policyOf(t, s)["URLAllowlist"]); len(got) != 1 || got[0] != "devtools://*" {
		t.Errorf("devtools allowlist: %v", got)
	}
	// A port the upstream holds moves the proxy's.
	s.Upstream = mustURL(t, "http://wiki.internal:3128")
	if ps := policyOf(t, s)["ProxySettings"].(map[string]any); ps["ProxyServer"] != "http://172.30.0.2:3129" {
		t.Errorf("proxy port beside the upstream's: %v", ps)
	}
	held := spec(t)
	hp := policyOf(t, held)
	if hp["ProxySettings"].(map[string]any)["ProxyServer"] != "socks5://172.30.0.2:1080" || !contains(strs(hp["URLBlocklist"]), "*") || len(strs(hp["URLAllowlist"])) != 1 {
		t.Errorf("held to its origins: %v %v %v", hp["ProxySettings"], hp["URLBlocklist"], hp["URLAllowlist"])
	}
}

func policyOf(t *testing.T, s Spec) map[string]any {
	t.Helper()
	raw, err := policyJSON(s, "172.30.0.2")
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
