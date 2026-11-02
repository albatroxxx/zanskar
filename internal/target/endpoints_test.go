// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// testCA stands in for a bundle where only the scheme rule is under test.
const testCA = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"

// TestApplicationEndpointsValidate: an application's further origins (ADR
// 0037, amended 2026-11-02) obey the upstream's rules, are normalised and
// named, never repeat the upstream or each other (as a browser compares
// origins), and are capped. An error names the row it is about.
func TestApplicationEndpointsValidate(t *testing.T) {
	app := &Target{Name: "Grafana", AppUpstream: "https://grafana.corp", AppEndpoints: []AppEndpoint{
		{Name: "  API  ", URL: " HTTPS://API.Corp:8443/ "},
		{URL: "http://10.0.0.9:3000"},
	}}
	if err := app.Validate(); err != nil {
		t.Fatalf("valid application: %v", err)
	}
	want := []AppEndpoint{{Name: "API", URL: "https://api.corp:8443"}, {Name: "10.0.0.9:3000", URL: "http://10.0.0.9:3000"}}
	if !reflect.DeepEqual(app.AppEndpoints, want) {
		t.Fatalf("normalised endpoints: %+v, want %+v", app.AppEndpoints, want)
	}
	if got := app.Endpoints(); len(got) != 3 || got[0] != (AppEndpoint{Name: "Grafana", URL: "https://grafana.corp"}) || got[1] != want[0] {
		t.Fatalf("Endpoints lists the upstream first under the application's name: %+v", got)
	}
	if app.Address != "grafana.corp" {
		t.Fatalf("the address stays the upstream's host: %q", app.Address)
	}

	empty := &Target{Name: "wiki", AppUpstream: "http://wiki.corp", AppEndpoints: []AppEndpoint{}}
	if err := empty.Validate(); err != nil || empty.AppEndpoints != nil {
		t.Fatalf("an empty list is stored as none: %v %+v", err, empty.AppEndpoints)
	}

	tooMany := make([]AppEndpoint, MaxAppEndpoints+1)
	for i := range tooMany {
		tooMany[i] = AppEndpoint{URL: fmt.Sprintf("http://e%d.corp", i)}
	}
	exactly := tooMany[:MaxAppEndpoints]
	if err := (&Target{Name: "full", AppUpstream: "http://home.corp", AppEndpoints: exactly}).Validate(); err != nil {
		t.Fatalf("%d endpoints beside the upstream are allowed: %v", MaxAppEndpoints, err)
	}

	for _, c := range []struct {
		name, wantIn string
		t            Target
	}{
		{"repeats the upstream", "app_endpoints[0] repeats the upstream", Target{AppUpstream: "https://a.corp", AppEndpoints: []AppEndpoint{{URL: "https://A.corp:443"}}}},
		{"repeats with a trailing dot", "app_endpoints[0] repeats the upstream", Target{AppUpstream: "https://a.corp", AppEndpoints: []AppEndpoint{{URL: "https://a.corp."}}}},
		{"repeats another", "app_endpoints[1] repeats app_endpoints[0]", Target{AppUpstream: "https://a.corp", AppEndpoints: []AppEndpoint{{URL: "http://b.corp"}, {URL: "http://b.corp:80"}}}},
		{"a path", "app_endpoints[0] must be the origin only", Target{AppUpstream: "https://a.corp", AppEndpoints: []AppEndpoint{{URL: "https://b.corp/admin"}}}},
		{"no scheme", "app_endpoints[1] must be http://host[:port]", Target{AppUpstream: "https://a.corp", AppEndpoints: []AppEndpoint{{URL: "https://b.corp"}, {URL: "c.corp"}}}},
		{"a bad port", "app_endpoints[0] port must be 1-65535", Target{AppUpstream: "https://a.corp", AppEndpoints: []AppEndpoint{{URL: "https://b.corp:0"}}}},
		{"a long name", "app_endpoints[0] name must be", Target{AppUpstream: "https://a.corp", AppEndpoints: []AppEndpoint{{Name: strings.Repeat("é", MaxEndpointNameLen+1), URL: "https://b.corp"}}}},
		{"a control character", "app_endpoints[0] name must be", Target{AppUpstream: "https://a.corp", AppEndpoints: []AppEndpoint{{Name: "API\nother", URL: "https://b.corp"}}}},
		{"too many", fmt.Sprintf("at most %d endpoints", MaxAppEndpoints), Target{AppUpstream: "http://home.corp", AppEndpoints: tooMany}},
		{"on a host", "app_endpoints belong to an application", Target{Address: "10.0.0.1", OSFamily: Linux, AppEndpoints: []AppEndpoint{{URL: "https://b.corp"}}}},
		{"on a database", "app_endpoints belong to an application", Target{Address: "db.corp", Engine: "postgres", TLSMode: TLSRequire, AppEndpoints: []AppEndpoint{{URL: "https://b.corp"}}}},
		{"a CA bundle with no https origin", "tls_ca applies to an https upstream or endpoint", Target{AppUpstream: "http://a.corp", AppEndpoints: []AppEndpoint{{URL: "http://b.corp"}}, TLSCA: testCA}},
	} {
		c.t.Name = "app"
		err := c.t.Validate()
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.wantIn) {
			t.Errorf("%s: got %v, want ErrInvalid containing %q", c.name, err, c.wantIn)
		}
	}

	// The CA bundle applies when any origin is https, not the upstream only:
	// an http application whose identity provider is https trusts a private CA.
	ca := &Target{Name: "app", AppUpstream: "http://a.corp", AppEndpoints: []AppEndpoint{{URL: "https://sso.corp"}}, TLSCA: "not a bundle"}
	if err := ca.Validate(); err == nil || !strings.Contains(err.Error(), "tls_ca must hold") {
		t.Fatalf("an https endpoint lets the bundle be checked as a bundle: %v", err)
	}
}

// TestApplicationEndpointsRepoOnEachBackend: the endpoints round-trip
// through the JSON column on SQLite and PostgreSQL, an update replaces them,
// and none is stored as none.
func TestApplicationEndpointsRepoOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		app := &Target{Name: "grafana", AppUpstream: "https://grafana.corp", AppEndpoints: []AppEndpoint{
			{Name: "API", URL: "https://api.corp:8443"}, {Name: "Sign-in", URL: "https://sso.corp"},
		}}
		if err := r.Create(ctx, app); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := r.Get(ctx, app.ID)
		if err != nil || !reflect.DeepEqual(got.AppEndpoints, app.AppEndpoints) {
			t.Fatalf("read back %+v (%v), want %+v", got.AppEndpoints, err, app.AppEndpoints)
		}
		got.AppEndpoints = []AppEndpoint{{Name: "API", URL: "https://api.corp:8443"}}
		if err := r.Update(ctx, got); err != nil {
			t.Fatalf("update: %v", err)
		}
		if again, _ := r.Get(ctx, app.ID); len(again.AppEndpoints) != 1 || again.AppEndpoints[0].URL != "https://api.corp:8443" {
			t.Fatalf("update replaces the list: %+v", again.AppEndpoints)
		}
		again, _ := r.Get(ctx, app.ID)
		again.AppEndpoints = nil
		if err := r.Update(ctx, again); err != nil {
			t.Fatalf("clear: %v", err)
		}
		var raw *string
		if err := db.QueryRowContext(ctx, db.Rebind(`SELECT app_endpoints FROM targets WHERE id = ?`), app.ID).Scan(&raw); err != nil || raw != nil {
			t.Fatalf("no endpoints is stored as NULL: %v %v", err, raw)
		}
		if cleared, _ := r.Get(ctx, app.ID); cleared.AppEndpoints != nil {
			t.Fatalf("read back none: %+v", cleared.AppEndpoints)
		}
	})
}

// TestApplicationOriginsRefusedAtSave: every origin of an application is
// held to the address rules as it is saved, the upstream included (the
// console sends no address for an application, so until 2026-11-02 only a
// session checked the upstream's host). Nothing is stored and the refusal
// is audited with the address that was refused.
func TestApplicationOriginsRefusedAtSave(t *testing.T) {
	e := newEnvWith(t, &Prober{})
	for i, c := range []struct {
		upstream string
		extra    []map[string]string
		refused  string
	}{
		{"http://169.254.169.254", nil, "169.254.169.254"},
		{"http://wiki.corp", []map[string]string{{"url": "https://api.corp"}, {"url": "http://[fd00:ec2::254]"}}, "fd00:ec2::254"},
		{"http://wiki.corp", []map[string]string{{"url": "http://127.0.0.1:8080"}}, "127.0.0.1"},
	} {
		body := map[string]any{"name": fmt.Sprintf("app-%d", i), "address": "", "app_upstream": c.upstream, "app_endpoints": c.extra}
		code, out := e.do("POST", "/api/v1/targets", body, e.admin)
		if code != 422 || out["code"] != "address_forbidden" {
			t.Errorf("%s %v: %d %v, want 422 address_forbidden", c.upstream, c.extra, code, out)
			continue
		}
		if d := details(t, e, "target.create"); d["address"] != c.refused || d["reason"] != "address_forbidden" {
			t.Errorf("refusal audit names %v, want %s", d, c.refused)
		}
	}
	if code, out := e.do("GET", "/api/v1/targets", nil, e.admin); code != 200 || len(out["items"].([]any)) != 0 {
		t.Fatalf("refused applications were stored: %d %v", code, out)
	}
}

// TestRemovedEndpointEndsSessions: an application's session reaches the
// origins it started with, so taking one off the application ends what is
// open on it, as moving a host does; adding one, or renaming one, does not.
// The audit trail carries the origins before and after.
func TestRemovedEndpointEndsSessions(t *testing.T) {
	e := newEnv(t)
	e.revoker.ended = 2
	body := func(extra ...map[string]string) map[string]any {
		return map[string]any{"name": "grafana", "app_upstream": "https://grafana.corp", "app_endpoints": extra}
	}
	api := map[string]string{"name": "API", "url": "https://api.corp"}
	sso := map[string]string{"name": "Sign-in", "url": "https://sso.corp"}
	id := e.mkTarget(t, body(api))
	if d := details(t, e, "target.create"); fmt.Sprint(d["origins"]) != "[https://grafana.corp https://api.corp]" {
		t.Fatalf("create audit origins: %v", d)
	}
	if code, out := e.do("PUT", "/api/v1/targets/"+id, body(api, sso), e.admin); code != 200 {
		t.Fatalf("add: %d %v", code, out)
	}
	renamed := map[string]string{"name": "Public API", "url": "https://api.corp"}
	if code, out := e.do("PUT", "/api/v1/targets/"+id, body(renamed, sso), e.admin); code != 200 {
		t.Fatalf("rename: %d %v", code, out)
	}
	if len(e.revoker.disabled) != 0 {
		t.Fatalf("adding or renaming an endpoint ended sessions: %v", e.revoker.disabled)
	}
	if code, out := e.do("PUT", "/api/v1/targets/"+id, body(sso), e.admin); code != 200 {
		t.Fatalf("remove: %d %v", code, out)
	}
	if got := e.revoker.disabled; len(got) != 1 || got[0] != id {
		t.Fatalf("removing an endpoint asked %v, want [%s]", got, id)
	}
	d := details(t, e, "target.update")
	if fmt.Sprint(d["origins_removed"]) != "[https://api.corp]" || d["live_sessions_ended"] != float64(2) {
		t.Fatalf("remove audit: %v", d)
	}
	after, _ := d["after"].(map[string]any)
	if fmt.Sprint(after["origins"]) != "[https://grafana.corp https://sso.corp]" {
		t.Fatalf("after origins: %v", after)
	}
}
