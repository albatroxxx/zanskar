// SPDX-License-Identifier: Apache-2.0

package browsergw

import (
	"encoding/json"
	"testing"
)

// TestPolicyNoSearchFromTheAddressBar (2026-11-03): with dependencies let
// out to public addresses, the address bar must not send what is typed to a
// search engine, so search and its suggestions are off by policy.
func TestPolicyNoSearchFromTheAddressBar(t *testing.T) {
	raw, err := policyJSON(spec(t), "172.30.0.2")
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"DefaultSearchProviderEnabled", "SearchSuggestEnabled"} {
		if v, ok := p[key]; !ok || v != false {
			t.Errorf("%s = %v, want false", key, v)
		}
	}
}
