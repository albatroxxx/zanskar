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
// and a label. The upstream must be exactly an origin, the label a DNS
// label derived from the name when not given, the address is the upstream's
// host, and the CA bundle belongs to an https upstream only.
func TestApplicationValidate(t *testing.T) {
	app := &Target{Name: "Wiki (internal)", AppUpstream: " HTTP://Wiki.Example.com:8080/ "}
	if err := app.Validate(); err != nil {
		t.Fatalf("valid application: %v", err)
	}
	if app.AppUpstream != "http://wiki.example.com:8080" || app.Address != "wiki.example.com" || app.AppLabel != "wiki-internal" || app.OSFamily != OtherOS || !app.IsApplication() {
		t.Fatalf("normalised application: %+v", app)
	}
	byIP := &Target{Name: "grafana", AppUpstream: "http://10.0.0.9:3000", AppLabel: " Grafana "}
	if err := byIP.Validate(); err != nil || byIP.Address != "10.0.0.9" || byIP.AppLabel != "grafana" {
		t.Fatalf("application by IP: %v %+v", err, byIP)
	}
	for _, bad := range []Target{
		{Name: "no scheme", AppUpstream: "wiki.example.com"},
		{Name: "ftp", AppUpstream: "ftp://wiki.example.com"},
		{Name: "path", AppUpstream: "http://wiki.example.com/wiki"},
		{Name: "query", AppUpstream: "http://wiki.example.com/?x=1"},
		{Name: "user", AppUpstream: "http://bob@wiki.example.com"},
		{Name: "port", AppUpstream: "http://wiki.example.com:70000"},
		{Name: "label", AppUpstream: "http://wiki.example.com", AppLabel: "Wiki_1"},
		{Name: "label dot", AppUpstream: "http://wiki.example.com", AppLabel: "a.b"},
		{Name: "both", AppUpstream: "http://wiki.example.com", Engine: "postgres", TLSMode: TLSRequire},
		{Name: "ca on http", AppUpstream: "http://wiki.example.com", TLSCA: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"},
		{Name: "ca garbage", AppUpstream: "https://wiki.example.com", TLSCA: "not a bundle"},
		{Name: "---", AppUpstream: "http://wiki.example.com"},
	} {
		if err := bad.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", bad.Name, err)
		}
	}
	// A host keeps no application fields, so a stale label never shadows an app.
	host := &Target{Name: "box", Address: "10.0.0.1", OSFamily: Linux, AppLabel: "box"}
	if err := host.Validate(); err != nil || host.AppLabel != "" {
		t.Fatalf("host: %v %+v", err, host)
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{
		"Wiki":                         "wiki",
		"Wiki (internal)":              "wiki-internal",
		"  Ops -- Dashboard  ":         "ops-dashboard",
		"grafana_prod":                 "grafana-prod",
		"ünïcode app":                  "n-code-app",
		"!!!":                          "",
		strings.Repeat("a", 70) + "-b": strings.Repeat("a", 63),
	} {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestApplicationRepo: the kind filter tells applications from hosts and
// databases, the inventory counts them apart, the label is unique among live
// applications and free again once one is retired, and GetByLabel finds the
// application the proxy serves.
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

	dup := &Target{Name: "wiki two", AppUpstream: "http://10.0.0.7", AppLabel: "wiki"}
	if err := repo.Create(ctx, dup); !errors.Is(err, ErrDuplicateLabel) {
		t.Fatalf("duplicate label: want ErrDuplicateLabel, got %v", err)
	}
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
	got, err := repo.GetByLabel(ctx, "wiki")
	if err != nil || got.ID != wiki.ID || got.AppUpstream != "http://10.0.0.5:8080" {
		t.Fatalf("GetByLabel: %v %+v", err, got)
	}
	// An update keeps its own label, and takes a free one.
	wiki.AppLabel = "docs"
	if err := repo.Update(ctx, wiki); err != nil {
		t.Fatalf("relabel: %v", err)
	}
	if _, err := repo.GetByLabel(ctx, "wiki"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old label still resolves: %v", err)
	}
	if err := repo.Delete(ctx, wiki.ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, &Target{Name: "docs again", AppUpstream: "http://10.0.0.8", AppLabel: "docs"}); err != nil {
		t.Fatalf("a retired application's label is free again: %v", err)
	}
}
