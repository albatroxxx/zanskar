// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/target"
)

// TestMyTargets: a user's target list holds the active targets their
// policies reach, with only the protocols those policies allow, the
// approval-gated ones marked as such. A target's address is shown only when
// it is a private IP; a public address or a hostname is withheld, so the
// list never hands out a way around the gateway.
func TestMyTargets(t *testing.T) {
	f := newConnectFixture(t)
	add := func(tg *target.Target) string {
		t.Helper()
		if tg.OSFamily == "" {
			tg.OSFamily = target.Linux
		}
		if err := f.h.Targets.Create(f.ctx, tg); err != nil {
			t.Fatalf("target %s: %v", tg.Name, err)
		}
		return tg.ID
	}
	public := add(&target.Target{Name: "public", Address: "203.0.113.10", Tags: map[string]string{"env": "test"}})
	named := add(&target.Target{Name: "named", Address: "box.example.com", Tags: map[string]string{"env": "test"}})
	pg := add(&target.Target{Name: "orders", Address: "10.1.0.5", Engine: "postgres", TLSMode: "require", Tags: map[string]string{"env": "test"}})
	add(&target.Target{Name: "elsewhere", Address: "10.9.9.9", Tags: map[string]string{"env": "other"}})

	rr := f.do("GET", "/api/v1/me/targets", "", nil, f.cookie, f.csrf)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rr.Code, rr.Body)
	}
	var page struct {
		Items []reachableTarget `json:"items"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	byName := map[string]reachableTarget{}
	for _, it := range page.Items {
		byName[it.Name] = it
	}

	if _, ok := byName["disabled"]; ok {
		t.Error("a disabled target is listed")
	}
	if _, ok := byName["elsewhere"]; ok {
		t.Error("a target no policy covers is listed")
	}
	if got := byName["ok"]; got.PrivateIP != "10.0.0.1" || !got.HostKeyReady {
		t.Errorf("private target: %+v", got)
	}
	// These two were created and never probed: their host key is unknown,
	// so the portal must not offer them as ready (review Q1, finding 1a: a
	// listing that said ready for every target passed every test).
	if got := byName["public"]; got.ID != public || got.PrivateIP != "" || got.HostKeyReady {
		t.Errorf("a public address must be withheld and an unknown key is not ready: %+v", got)
	}
	if got := byName["named"]; got.ID != named || got.PrivateIP != "" || got.HostKeyReady {
		t.Errorf("a hostname must be withheld and an unknown key is not ready: %+v", got)
	}
	if got := byName["orders"]; got.ID != pg || got.Engine != "postgres" || !contains(got.Allowed, "database") {
		t.Errorf("database target: %+v", got)
	}
	if got := byName["jit-box"]; !contains(got.Allowed, "ssh") || !contains(got.RequiresApproval, "ssh") {
		t.Errorf("approval-gated target must say so: %+v", got)
	}
	if got := byName["ok"]; len(got.RequiresApproval) != 0 {
		t.Errorf("standing access marked as approval-gated: %+v", got)
	}
	for _, it := range page.Items {
		for _, p := range it.Allowed {
			if p == "vnc" {
				t.Errorf("%s offers vnc, which no policy of alice's allows", it.Name)
			}
		}
	}

	// A user with no policy sees an empty list, not an error.
	bob, bobCSRF := f.signIn(t, "bob")
	rr = f.do("GET", "/api/v1/me/targets", "", nil, bob, bobCSRF)
	if rr.Code != http.StatusOK || rr.Body.String() != "{\"items\":[]}\n" {
		t.Fatalf("bob's list: %d %s", rr.Code, rr.Body)
	}
}

// TestMyTargetsApplications: an application (ADR 0033) is listed, with the
// address the browser opens it at and never its upstream, only when a policy
// grants http on it and the gateway has an apps domain to serve it under.
func TestMyTargetsApplications(t *testing.T) {
	f := newConnectFixture(t)
	wiki := &target.Target{Name: "wiki", AppUpstream: "http://10.0.0.50:8080", Tags: map[string]string{"env": "test"}}
	if err := f.h.Targets.Create(f.ctx, wiki); err != nil {
		t.Fatal(err)
	}
	list := func() map[string]reachableTarget {
		t.Helper()
		rr := f.do("GET", "/api/v1/me/targets", "", nil, f.cookie, f.csrf)
		if rr.Code != http.StatusOK {
			t.Fatalf("list: %d %s", rr.Code, rr.Body)
		}
		var page struct {
			Items []reachableTarget `json:"items"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		byName := map[string]reachableTarget{}
		for _, it := range page.Items {
			byName[it.Name] = it
		}
		return byName
	}
	// No apps domain: the application cannot be opened, so it is not offered.
	if _, ok := list()["wiki"]; ok {
		t.Fatal("an application is listed with no apps domain to serve it")
	}
	f.h.AppURL = func(_ *http.Request, label string) string { return "https://" + label + ".apps.example.com/" }
	// No policy grants http yet: test-all grants ssh, rdp, winrm and database.
	if _, ok := list()["wiki"]; ok {
		t.Fatal("an application is listed without a policy granting http")
	}
	p := &policy.Policy{Name: "apps", GroupID: f.opsID, Enabled: true, IdleTimeoutMinutes: 15, Selector: policy.Selector{Tags: map[string]string{"env": "test"}}, Protocols: []string{"http"}}
	if err := f.h.Policies.Create(f.ctx, p); err != nil {
		t.Fatal(err)
	}
	got, ok := list()["wiki"]
	if !ok || got.Kind != "application" || got.Label != "wiki" || got.URL != "https://wiki.apps.example.com/" || !contains(got.Allowed, "http") || got.PrivateIP != "" {
		t.Fatalf("application entry: %+v", got)
	}
	if strings.Contains(string(mustJSON(t, got)), "10.0.0.50") {
		t.Fatalf("the upstream leaked into the listing: %+v", got)
	}
	// Opening it goes through the browser, not a ticket.
	rr := f.do("POST", "/api/v1/connect", "application/json", strings.NewReader(`{"target_id":"`+wiki.ID+`","protocol":"http"}`), f.cookie, f.csrf)
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("connect over http: %d %s", rr.Code, rr.Body)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func contains(xs []string, x string) bool {
	return slices.Contains(xs, x)
}
