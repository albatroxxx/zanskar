// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// TestApplicationPrivateValidate (ADR 0037, amended 2026-11-03, later): an
// application's private allowances are networks written as their own
// address in private space and hosts as host:port, normalised, none
// repeating; what is public, link-local, a metadata service or malformed
// is refused with the entry named; nothing is stored as none; a host or a
// database holds none.
func TestApplicationPrivateValidate(t *testing.T) {
	app := &Target{Name: "Grafana", AppUpstream: "https://grafana.corp", AppPrivate: &AppPrivate{
		Networks: []string{" 10.20.0.0/16 ", "fd00:1::/64"},
		Hosts:    []string{"CDN.corp.:443", "10.0.0.9:8443", "[fd00::5]:443"},
	}}
	if err := app.Validate(); err != nil {
		t.Fatalf("valid: %v", err)
	}
	want := &AppPrivate{Networks: []string{"10.20.0.0/16", "fd00:1::/64"}, Hosts: []string{"cdn.corp:443", "10.0.0.9:8443", "[fd00::5]:443"}}
	if !reflect.DeepEqual(app.AppPrivate, want) {
		t.Fatalf("normalised: %+v, want %+v", app.AppPrivate, want)
	}
	empty := &Target{Name: "wiki", AppUpstream: "http://wiki.corp", AppPrivate: &AppPrivate{Networks: []string{}, Hosts: nil}}
	if err := empty.Validate(); err != nil || empty.AppPrivate != nil {
		t.Fatalf("nothing is stored as none: %v %+v", err, empty.AppPrivate)
	}
	for _, c := range []struct {
		name string
		p    AppPrivate
		want string
	}{
		{"a host address as a network", AppPrivate{Networks: []string{"10.20.0.1/16"}}, "networks[0]: 10.20.0.1/16 is not the network's address; use 10.20.0.0/16"},
		{"a public network", AppPrivate{Networks: []string{"8.8.8.0/24"}}, "networks[0]: 8.8.8.0/24 is public, not a private network"},
		{"link-local", AppPrivate{Networks: []string{"169.254.0.0/16"}}, "is link-local, not a private network"},
		{"shared address space", AppPrivate{Networks: []string{"100.64.0.0/10"}}, "shared address space"},
		{"not a cidr", AppPrivate{Networks: []string{"10.20.0.0"}}, "networks[0] must be a network in CIDR form"},
		{"a repeated network", AppPrivate{Networks: []string{"10.0.0.0/8", "10.0.0.0/8"}}, "networks[1] repeats 10.0.0.0/8"},
		{"a host without a port", AppPrivate{Hosts: []string{"cdn.corp"}}, "hosts[0] must be host:port"},
		{"a bad port", AppPrivate{Hosts: []string{"cdn.corp:99999"}}, "hosts[0] has no valid port"},
		{"a public address", AppPrivate{Hosts: []string{"1.1.1.1:443"}}, "hosts[0]: 1.1.1.1 is public, not a private address"},
		{"a metadata service", AppPrivate{Hosts: []string{"169.254.169.254:80"}}, "is link-local, not a private address"},
		{"a repeated host", AppPrivate{Hosts: []string{"cdn.corp:443", "CDN.corp:443"}}, "hosts[1] repeats cdn.corp:443"},
		{"not a name", AppPrivate{Hosts: []string{"not a name:443"}}, "is not a host name"},
	} {
		x := &Target{Name: "wiki", AppUpstream: "http://wiki.corp", AppPrivate: &c.p}
		if err := x.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	many := make([]string, MaxPrivateEntries+1)
	for i := range many {
		many[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}
	if err := (&Target{Name: "wiki", AppUpstream: "http://wiki.corp", AppPrivate: &AppPrivate{Networks: many}}).Validate(); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("too many: %v", err)
	}
	host := &Target{Name: "web", Address: "10.0.0.5", OSFamily: Linux, AppPrivate: &AppPrivate{Hosts: []string{"cdn.corp:443"}}}
	if err := host.Validate(); err == nil || !strings.Contains(err.Error(), "app_private belongs to an application") {
		t.Errorf("a host with private dependencies: %v", err)
	}
}

// TestApplicationPrivateAndRefusalsRepoOnEachBackend: the allowances are
// stored and read back on both engines, none as NULL; what a session's
// relay refused is kept per application, counted on across sightings,
// listed newest first, and forgotten on request.
func TestApplicationPrivateAndRefusalsRepoOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		app := &Target{Name: "grafana", AppUpstream: "https://grafana.corp", AppPrivate: &AppPrivate{Networks: []string{"10.20.0.0/16"}, Hosts: []string{"cdn.corp:443"}}}
		if err := r.Create(ctx, app); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := r.Get(ctx, app.ID)
		if err != nil || !reflect.DeepEqual(got.AppPrivate, app.AppPrivate) {
			t.Fatalf("read back %+v (%v)", got.AppPrivate, err)
		}
		got.AppPrivate = nil
		if err := r.Update(ctx, got); err != nil {
			t.Fatalf("clear: %v", err)
		}
		var raw *string
		if err := db.QueryRowContext(ctx, db.Rebind(`SELECT app_private FROM targets WHERE id = ?`), app.ID).Scan(&raw); err != nil || raw != nil {
			t.Fatalf("none is NULL: %v %v", err, raw)
		}
		t0 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
		first := []Refusal{
			{Host: "fonts.corp", Port: 443, Why: "private", What: "font", From: "https://grafana.corp", Count: 2, FirstSeen: t0, LastSeen: t0},
			{Host: "169.254.169.254", Port: 80, Why: "link-local", What: "image", From: "https://grafana.corp", Count: 1, FirstSeen: t0, LastSeen: t0},
		}
		if err := r.RecordRefusals(ctx, app.ID, first); err != nil {
			t.Fatalf("record: %v", err)
		}
		later := t0.Add(time.Hour)
		if err := r.RecordRefusals(ctx, app.ID, []Refusal{{Host: "fonts.corp", Port: 443, Why: "private", What: "font", From: "https://grafana.corp", Count: 3, FirstSeen: later, LastSeen: later}}); err != nil {
			t.Fatalf("record again: %v", err)
		}
		list, err := r.ListRefusals(ctx, app.ID)
		if err != nil || len(list) != 2 {
			t.Fatalf("list: %v %+v", err, list)
		}
		if f := list[0]; f.Host != "fonts.corp" || f.Count != 5 || !f.FirstSeen.Equal(t0) || !f.LastSeen.Equal(later) {
			t.Fatalf("counted on and moved up: %+v", f)
		}
		if list[1].Host != "169.254.169.254" || list[1].Why != "link-local" {
			t.Fatalf("the other row: %+v", list[1])
		}
		if err := r.RecordRefusals(ctx, app.ID, nil); err != nil {
			t.Fatalf("nothing to record: %v", err)
		}
		if err := r.ClearRefusals(ctx, app.ID); err != nil {
			t.Fatalf("clear: %v", err)
		}
		if list, _ := r.ListRefusals(ctx, app.ID); len(list) != 0 {
			t.Fatalf("after clear: %+v", list)
		}
	})
}

// TestPrivateAllowanceRemovedEndsSessions: taking a private allowance off an
// application ends its open sessions, whose relays still hold it; adding
// one does not. The audit trail carries the allowances before and after.
// The learned list is read through the API, newest first, and cleared with
// an audited DELETE.
func TestPrivateAllowanceRemovedEndsSessions(t *testing.T) {
	e := newEnv(t)
	e.revoker.ended = 1
	body := func(p map[string]any) map[string]any {
		return map[string]any{"name": "grafana", "app_upstream": "https://grafana.corp", "app_private": p}
	}
	id := e.mkTarget(t, body(map[string]any{"hosts": []string{"cdn.corp:443"}}))
	if d := details(t, e, "target.create"); fmt.Sprint(d["private"]) != "[cdn.corp:443]" {
		t.Fatalf("create audit: %v", d)
	}
	if code, out := e.do("PUT", "/api/v1/targets/"+id, body(map[string]any{"networks": []string{"10.20.0.0/16"}, "hosts": []string{"cdn.corp:443"}}), e.admin); code != 200 {
		t.Fatalf("add: %d %v", code, out)
	}
	if len(e.revoker.disabled) != 0 {
		t.Fatalf("adding an allowance ended sessions: %v", e.revoker.disabled)
	}
	if code, out := e.do("PUT", "/api/v1/targets/"+id, body(map[string]any{"networks": []string{"10.20.0.0/16"}}), e.admin); code != 200 {
		t.Fatalf("remove: %d %v", code, out)
	}
	if got := e.revoker.disabled; len(got) != 1 || got[0] != id {
		t.Fatalf("removing an allowance asked %v, want [%s]", got, id)
	}
	d := details(t, e, "target.update")
	after, _ := d["after"].(map[string]any)
	if fmt.Sprint(d["private_removed"]) != "[cdn.corp:443]" || fmt.Sprint(after["private"]) != "[10.20.0.0/16]" {
		t.Fatalf("remove audit: %v", d)
	}
	if code, out := e.do("PUT", "/api/v1/targets/"+id, body(map[string]any{"hosts": []string{"cdn.corp"}}), e.admin); code != 400 || !strings.Contains(fmt.Sprint(out["message"]), "app_private.hosts[0]") {
		t.Fatalf("a bad host: %d %v", code, out)
	}
	// What a session's relay refused, through the API.
	if err := NewRepo(e.db).RecordRefusals(context.Background(), id, []Refusal{{Host: "fonts.corp", Port: 443, Why: "private", What: "font", From: "https://grafana.corp", Count: 2}}); err != nil {
		t.Fatal(err)
	}
	code, out := e.do("GET", "/api/v1/targets/"+id+"/dependencies", nil, e.admin)
	items, _ := out["items"].([]any)
	if code != 200 || len(items) != 1 {
		t.Fatalf("list: %d %v", code, out)
	}
	if row, _ := items[0].(map[string]any); row["host"] != "fonts.corp" || row["port"] != float64(443) || row["why"] != "private" || row["what"] != "font" || row["count"] != float64(2) {
		t.Fatalf("row: %v", items[0])
	}
	if code, _ := e.do("DELETE", "/api/v1/targets/"+id+"/dependencies", nil, e.admin); code != 204 {
		t.Fatalf("clear: %d", code)
	}
	if d := details(t, e, "target.update"); d["dependencies_cleared"] != true {
		t.Fatalf("clear audit: %v", d)
	}
	if _, out := e.do("GET", "/api/v1/targets/"+id+"/dependencies", nil, e.admin); len(out["items"].([]any)) != 0 {
		t.Fatalf("after clear: %v", out)
	}
	if code, _ := e.do("GET", "/api/v1/targets/nope/dependencies", nil, e.admin); code != 404 {
		t.Fatalf("unknown target: %d", code)
	}
}
