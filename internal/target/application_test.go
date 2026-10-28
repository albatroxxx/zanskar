// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// TestApplicationValidate: an application (ADR 0033) is its upstream origin
// (ADR 0034). The upstream must be exactly an origin, the address is the
// upstream's host, and the CA bundle belongs to an https upstream only.
func TestApplicationValidate(t *testing.T) {
	app := &Target{Name: "Wiki (internal)", AppUpstream: " HTTP://Wiki.Example.com:8080/ "}
	if err := app.Validate(); err != nil {
		t.Fatalf("valid application: %v", err)
	}
	if app.AppUpstream != "http://wiki.example.com:8080" || app.Address != "wiki.example.com" || app.OSFamily != OtherOS || !app.IsApplication() {
		t.Fatalf("normalised application: %+v", app)
	}
	byIP := &Target{Name: "grafana", AppUpstream: "http://10.0.0.9:3000"}
	if err := byIP.Validate(); err != nil || byIP.Address != "10.0.0.9" {
		t.Fatalf("application by IP: %v %+v", err, byIP)
	}
	for _, bad := range []Target{
		{Name: "no scheme", AppUpstream: "wiki.example.com"},
		{Name: "ftp", AppUpstream: "ftp://wiki.example.com"},
		{Name: "path", AppUpstream: "http://wiki.example.com/wiki"},
		{Name: "query", AppUpstream: "http://wiki.example.com/?x=1"},
		{Name: "user", AppUpstream: "http://bob@wiki.example.com"},
		{Name: "port", AppUpstream: "http://wiki.example.com:70000"},
		{Name: "both", AppUpstream: "http://wiki.example.com", Engine: "postgres", TLSMode: TLSRequire},
		{Name: "ca on http", AppUpstream: "http://wiki.example.com", TLSCA: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"},
		{Name: "ca garbage", AppUpstream: "https://wiki.example.com", TLSCA: "not a bundle"},
	} {
		if err := bad.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", bad.Name, err)
		}
	}
	// A host keeps no application fields, so a stale label never shadows an app.
	host := &Target{Name: "box", Address: "10.0.0.1", OSFamily: Linux}
	if err := host.Validate(); err != nil || host.IsApplication() {
		t.Fatalf("host: %v %+v", err, host)
	}
}

// TestApplicationRepo: the kind filter tells applications from hosts and
// databases, the inventory counts them apart, and an application's upstream
// round-trips through create, update and read.
func TestApplicationRepo(t *testing.T) {
	ctx := context.Background()
	repo := NewRepo(storetest.Open(t))
	add := func(tg *Target) {
		t.Helper()
		if tg.OSFamily == "" {
			tg.OSFamily = Linux
		}
		if err := repo.Create(ctx, tg); err != nil {
			t.Fatalf("create %s: %v", tg.Name, err)
		}
	}
	add(&Target{Name: "box", Address: "10.0.0.1"})
	add(&Target{Name: "orders", Address: "db.internal", Engine: "postgres", TLSMode: TLSRequire})
	wiki := &Target{Name: "wiki", AppUpstream: "http://10.0.0.5:8080"}
	add(wiki)
	add(&Target{Name: "grafana", AppUpstream: "https://10.0.0.6", Status: StatusDisabled})

	for kind, want := range map[string][]string{KindHost: {"box"}, KindDatabase: {"orders"}, KindApplication: {"grafana", "wiki"}, "": {"box", "grafana", "orders", "wiki"}} {
		list, _, err := repo.List(ctx, "", 50, ListFilter{Kind: kind})
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, tg := range list {
			names = append(names, tg.Name)
		}
		if strings.Join(names, ",") != strings.Join(want, ",") {
			t.Errorf("kind %q: got %v, want %v", kind, names, want)
		}
	}
	inv, err := repo.CountInventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Hosts != 1 || inv.Databases != 1 || inv.Applications != 1 {
		t.Fatalf("inventory: %+v", inv)
	}
	got, err := repo.Get(ctx, wiki.ID)
	if err != nil || got.AppUpstream != "http://10.0.0.5:8080" || !got.IsApplication() {
		t.Fatalf("application read back: %v %+v", err, got)
	}
	wiki.AppUpstream = "http://10.0.0.5:9090"
	if err := repo.Update(ctx, wiki); err != nil {
		t.Fatalf("update upstream: %v", err)
	}
	if got, err := repo.Get(ctx, wiki.ID); err != nil || got.AppUpstream != "http://10.0.0.5:9090" || got.Address != "10.0.0.5" {
		t.Fatalf("updated upstream: %v %+v", err, got)
	}
	if err := repo.Delete(ctx, wiki.ID); err != nil {
		t.Fatal(err)
	}
}
