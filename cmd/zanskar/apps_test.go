// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// TestAppsDomainChecker: the apps domain may not hold the console's own
// host, or the console's requests would reach the applications proxy; with
// no public URL there is nothing to compare.
func TestAppsDomainChecker(t *testing.T) {
	check := appsDomainChecker("https://GW.example.com:8443")
	for domain, ok := range map[string]bool{
		"apps.example.com":    true,
		"apps.gw.example.com": true,
		"":                    true,
		"example.com":         false,
		"gw.example.com":      false,
		"Example.COM":         false,
	} {
		if err := check(domain); (err == nil) != ok {
			t.Errorf("check(%q) = %v, want ok=%v", domain, err, ok)
		}
	}
	if err := appsDomainChecker("")("example.com"); err != nil {
		t.Errorf("without a public URL: %v", err)
	}
}
