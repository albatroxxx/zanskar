// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// TestApplicationDependenciesValidate (2026-11-03): an application's
// dependencies are public unless said otherwise, the word is normalised,
// any other word is refused, and a host or a database holds none.
func TestApplicationDependenciesValidate(t *testing.T) {
	app := &Target{Name: "Grafana", AppUpstream: "https://grafana.corp"}
	if err := app.Validate(); err != nil || app.AppDependencies != DependenciesPublic {
		t.Fatalf("default: %v %q, want public", err, app.AppDependencies)
	}
	held := &Target{Name: "Grafana", AppUpstream: "https://grafana.corp", AppDependencies: " Origins "}
	if err := held.Validate(); err != nil || held.AppDependencies != DependenciesOrigins {
		t.Fatalf("origins: %v %q", err, held.AppDependencies)
	}
	bad := &Target{Name: "Grafana", AppUpstream: "https://grafana.corp", AppDependencies: "anywhere"}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "app_dependencies must be public or origins") {
		t.Fatalf("a made-up word: %v", err)
	}
	host := &Target{Name: "web", Address: "10.0.0.5", OSFamily: Linux, AppDependencies: DependenciesPublic}
	if err := host.Validate(); err == nil || !strings.Contains(err.Error(), "app_dependencies belong to an application") {
		t.Fatalf("a host with dependencies: %v", err)
	}
	plain := &Target{Name: "web", Address: "10.0.0.5", OSFamily: Linux}
	if err := plain.Validate(); err != nil || plain.AppDependencies != "" {
		t.Fatalf("a host holds none: %v %q", err, plain.AppDependencies)
	}
}

// TestApplicationDependenciesRepoOnEachBackend: the word is stored and read
// back on both engines, a host stores NULL, and an application row without
// one (from before migration 0048 filled it) reads as public.
func TestApplicationDependenciesRepoOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		app := &Target{Name: "grafana", AppUpstream: "https://grafana.corp"}
		if err := r.Create(ctx, app); err != nil {
			t.Fatalf("create: %v", err)
		}
		if got, err := r.Get(ctx, app.ID); err != nil || got.AppDependencies != DependenciesPublic {
			t.Fatalf("read back %q (%v), want public", got.AppDependencies, err)
		}
		app.AppDependencies = DependenciesOrigins
		if err := r.Update(ctx, app); err != nil {
			t.Fatalf("update: %v", err)
		}
		if got, _ := r.Get(ctx, app.ID); got.AppDependencies != DependenciesOrigins {
			t.Fatalf("read back %q, want origins", got.AppDependencies)
		}
		if _, err := db.ExecContext(ctx, db.Rebind(`UPDATE targets SET app_dependencies = NULL WHERE id = ?`), app.ID); err != nil {
			t.Fatal(err)
		}
		if got, _ := r.Get(ctx, app.ID); got.AppDependencies != DependenciesPublic {
			t.Fatalf("a row without the word reads %q, want public", got.AppDependencies)
		}
		host := &Target{Name: "web", Address: "10.0.0.5", OSFamily: Linux}
		if err := r.Create(ctx, host); err != nil {
			t.Fatalf("create host: %v", err)
		}
		var raw *string
		if err := db.QueryRowContext(ctx, db.Rebind(`SELECT app_dependencies FROM targets WHERE id = ?`), host.ID).Scan(&raw); err != nil || raw != nil {
			t.Fatalf("a host stores NULL: %v %v", err, raw)
		}
	})
}

// TestNarrowedDependenciesEndSessions: holding an application to its
// origins ends the sessions open on it, whose relays let dependencies out;
// widening again does not. The audit trail says the word before and after,
// and a made-up word is refused with the field named.
func TestNarrowedDependenciesEndSessions(t *testing.T) {
	e := newEnv(t)
	e.revoker.ended = 1
	body := func(deps string) map[string]any {
		return map[string]any{"name": "grafana", "app_upstream": "https://grafana.corp", "app_dependencies": deps}
	}
	id := e.mkTarget(t, body(""))
	if d := details(t, e, "target.create"); d["dependencies"] != DependenciesPublic {
		t.Fatalf("create audit: %v", d)
	}
	if code, out := e.do("PUT", "/api/v1/targets/"+id, body("anywhere"), e.admin); code != 400 || !strings.Contains(fmt.Sprint(out["message"]), "app_dependencies") {
		t.Fatalf("a made-up word: %d %v", code, out)
	}
	if code, out := e.do("PUT", "/api/v1/targets/"+id, body("origins"), e.admin); code != 200 || out["app_dependencies"] != "origins" {
		t.Fatalf("narrow: %d %v", code, out)
	}
	if got := e.revoker.disabled; len(got) != 1 || got[0] != id {
		t.Fatalf("narrowing asked %v, want [%s]", got, id)
	}
	d := details(t, e, "target.update")
	before, _ := d["before"].(map[string]any)
	after, _ := d["after"].(map[string]any)
	if d["dependencies_narrowed"] != true || d["live_sessions_ended"] != float64(1) || before["dependencies"] != "public" || after["dependencies"] != "origins" {
		t.Fatalf("narrow audit: %v", d)
	}
	if code, out := e.do("PUT", "/api/v1/targets/"+id, body("public"), e.admin); code != 200 || out["app_dependencies"] != "public" {
		t.Fatalf("widen: %d %v", code, out)
	}
	if got := e.revoker.disabled; len(got) != 1 {
		t.Fatalf("widening ended sessions: %v", got)
	}
	if d := details(t, e, "target.update"); d["dependencies_narrowed"] != nil {
		t.Fatalf("widen audit: %v", d)
	}
}
