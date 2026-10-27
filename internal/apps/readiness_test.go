// SPDX-License-Identifier: Apache-2.0

package apps

import (
	"errors"
	"strings"
	"testing"
)

// TestReadinessListsEveryPrerequisite: the checklist names the apps domain,
// the public address and the certificate with their state and what to do,
// in every combination an operator meets on the way to the first
// application; Ready stays the one-line refusal the enrolment uses.
func TestReadinessListsEveryPrerequisite(t *testing.T) {
	byKey := func(cs []Check) map[string]Check {
		m := map[string]Check{}
		for _, c := range cs {
			m[c.Key] = c
		}
		return m
	}
	serving := func(d string) error { return errors.New("upload a certificate for *." + d + " first") }
	h := &Handler{Domain: func() string { return "" }, PublicURL: "", TLSReady: serving}
	ready, cs := h.Readiness()
	m := byKey(cs)
	if ready || len(cs) != 3 || m["domain"].OK || m["public_url"].OK || m["certificate"].OK {
		t.Fatalf("nothing configured: ready=%v %+v", ready, cs)
	}
	if !strings.Contains(m["domain"].Detail, "apps.example.com") || !strings.Contains(m["public_url"].Detail, "ZANSKAR_PUBLIC_URL") || m["certificate"].Detail != "waits for the apps domain" {
		t.Fatalf("details must say what to do: %+v", cs)
	}
	if h.Ready() == nil {
		t.Fatal("Ready must refuse while a prerequisite is missing")
	}

	// Domain and address set, the gateway serving TLS without the certificate.
	h = &Handler{Domain: func() string { return "apps.example.com" }, PublicURL: "https://gateway.example.com", TLSReady: serving}
	ready, cs = h.Readiness()
	m = byKey(cs)
	if ready || !m["domain"].OK || !m["public_url"].OK || m["certificate"].OK || !strings.Contains(m["certificate"].Detail, "*.apps.example.com") {
		t.Fatalf("certificate missing: ready=%v %+v", ready, cs)
	}
	if err := h.Ready(); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("Ready must name the certificate: %v", err)
	}

	// Behind a proxy that terminates TLS: no certificate is asked of the gateway.
	h = &Handler{Domain: func() string { return "apps.example.com" }, PublicURL: "https://gateway.example.com"}
	ready, cs = h.Readiness()
	m = byKey(cs)
	if !ready || !m["certificate"].OK || !strings.Contains(m["certificate"].Detail, "proxy") {
		t.Fatalf("proxy mode: ready=%v %+v", ready, cs)
	}
	if h.Ready() != nil {
		t.Fatal("Ready must pass behind a proxy")
	}

	// Everything in place with the gateway serving TLS.
	h.TLSReady = func(string) error { return nil }
	if ready, cs = h.Readiness(); !ready || !byKey(cs)["certificate"].OK {
		t.Fatalf("all set: ready=%v %+v", ready, cs)
	}
}
