// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/idp"
)

type listed []idp.Identity

func (l listed) Users(context.Context, *idp.Opened) ([]idp.Identity, error) { return l, nil }

// TestSyncRoutes (ADR 0035): the status of a provider's user sync, and a
// run while the administrator waits, which is audited under them even when
// it changes nothing. A provider without sync on, or a gateway without the
// sync, answers 409 with the reason.
func TestSyncRoutes(t *testing.T) {
	e := newEnv(t)
	create := func(name string, sync bool) string {
		t.Helper()
		code, out, raw := e.do(t, "POST", "/api/v1/identity-providers", map[string]any{"name": name, "type": "oidc", "config": map[string]any{
			"oidc": map[string]any{"issuer": "https://kc.example/realms/" + name, "client_id": "cid", "client_secret": "s"}, "auto_provision": true, "sync_users": sync}})
		if code != http.StatusCreated {
			t.Fatalf("create: %d %s", code, raw)
		}
		return out["id"].(string)
	}
	on, off := create("on", true), create("off", false)

	if code, out, _ := e.do(t, "POST", "/api/v1/identity-providers/"+on+"/sync", nil); code != http.StatusConflict || out["code"] != "sync_unavailable" {
		t.Fatalf("no syncer: %d %v", code, out)
	}
	e.h.Sync = &idp.Syncer{Providers: e.repo, Provisioner: &idp.Provisioner{Users: e.users}, Audit: e.audit,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Directories: map[idp.Type]idp.Directory{idp.TypeOIDC: listed{{ExternalID: "k1", Username: "kim", DisplayName: "Kim"}}}}

	code, out, _ := e.do(t, "GET", "/api/v1/identity-providers/"+on+"/sync", nil)
	if code != http.StatusOK || out["enabled"] != true || out["interval_minutes"] != float64(15) || out["last"] != nil || out["running"] != false {
		t.Fatalf("status before a run: %d %v", code, out)
	}
	if code, out, _ := e.do(t, "POST", "/api/v1/identity-providers/"+off+"/sync", nil); code != http.StatusConflict || out["code"] != "sync_off" {
		t.Fatalf("sync off: %d %v", code, out)
	}
	code, out, raw := e.do(t, "POST", "/api/v1/identity-providers/"+on+"/sync", map[string]any{"apply_removals": true})
	last, _ := out["last"].(map[string]any)
	if code != http.StatusOK || last == nil || last["created"] != float64(1) || last["ok"] != true {
		t.Fatalf("run: %d %s", code, raw)
	}
	if _, err := e.users.GetByUsername(context.Background(), "kim"); err != nil {
		t.Fatalf("kim: %v", err)
	}
	// A second run changes nothing and is still recorded, under the admin.
	if code, _, _ := e.do(t, "POST", "/api/v1/identity-providers/"+on+"/sync", nil); code != http.StatusOK {
		t.Fatalf("second run: %d", code)
	}
	evs, _, err := e.audit.List(context.Background(), audit.Filter{Action: audit.IdPSync, Limit: 10})
	if err != nil || len(evs) != 2 || evs[0].ActorUserID == "" {
		t.Fatalf("sync events: %+v %v", evs, err)
	}
	if !strings.Contains(string(evs[1].Details), `"forced":true`) {
		t.Fatalf("the forced run must say so: %s", evs[1].Details)
	}
	if code, _, _ := e.do(t, "POST", "/api/v1/identity-providers/"+on+"/sync", "not an object"); code != http.StatusBadRequest {
		t.Fatalf("bad body: %d", code)
	}
	if code, _, _ := e.do(t, "GET", "/api/v1/identity-providers/nope/sync", nil); code != http.StatusNotFound {
		t.Fatalf("unknown provider: %d", code)
	}
}
