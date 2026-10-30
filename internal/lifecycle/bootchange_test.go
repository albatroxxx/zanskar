// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/bootedit"
)

// TestBootChangeGuards (ADR 0020, amended 2026-10-30): a change to the
// environment file asks for a fresh authenticator code, a systemd host with
// a state directory, and passes the helper's own checks here, before any
// drain starts.
func TestBootChangeGuards(t *testing.T) {
	e := newHostEnv(t)
	if code, out := e.do("POST", "/api/v1/admin/settings/boot", map[string]any{"values": map[string]string{"ZANSKAR_LOG_FORMAT": "text"}}); code != 409 || out["code"] != "unsupported_supervisor" {
		t.Fatalf("no state dir: %d %v", code, out)
	}
	e.h.StateDir = t.TempDir()
	if code, out := e.do("POST", "/api/v1/admin/settings/boot", map[string]any{"values": map[string]string{"ZANSKAR_LOG_FORMAT": "text"}}); code != 403 || out["code"] != "step_up_required" {
		t.Fatalf("stale code: %d %v", code, out)
	}
	if err := e.sessions.MarkMFAProved(context.Background(), e.sessID); err != nil {
		t.Fatal(err)
	}
	for _, body := range []map[string]any{
		{"values": map[string]string{"ZANSKAR_DB_DSN": "postgres://evil"}},
		{"values": map[string]string{"ZANSKAR_ISSUER": "a\nZANSKAR_DOCKER_PATH=/tmp/sh"}},
		{"tls_mode": "file"},
		{},
	} {
		if code, out := e.do("POST", "/api/v1/admin/settings/boot", body); code != 400 || out["code"] != "invalid_change" {
			t.Fatalf("%v: %d %v", body, code, out)
		}
	}
	if e.ctrl.Draining() {
		t.Fatal("a refused change started a drain")
	}
}

// TestBootChangeWritesTheRequest: the change is audited with its values,
// the gateway drains, and the request the helper reads is written; when the
// helper refuses it, the gateway serves again and says why.
func TestBootChangeWritesTheRequest(t *testing.T) {
	e := newHostEnv(t)
	dir := t.TempDir()
	e.h.StateDir, e.h.installPoll = dir, 5*time.Millisecond
	if err := e.sessions.MarkMFAProved(context.Background(), e.sessID); err != nil {
		t.Fatal(err)
	}
	code, out := e.do("POST", "/api/v1/admin/settings/boot", map[string]any{"tls_mode": "managed", "values": map[string]string{"ZANSKAR_PUBLIC_URL": "https://gw.example.com"}, "wait_minutes": 0})
	if code != 202 || out["id"] == "" {
		t.Fatalf("change: %d %v", code, out)
	}
	id := out["id"].(string)
	path := filepath.Join(dir, bootedit.RequestFile)
	e.waitFor(func() bool { _, err := os.Stat(path); return err == nil })
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	req, err := bootedit.ParseRequest(f)
	_ = f.Close()
	if err != nil || req.ID != id || req.TLSMode != "managed" || req.Values["ZANSKAR_PUBLIC_URL"] != "https://gw.example.com" || req.RequestedBy == "" {
		t.Fatalf("request: %+v %v", req, err)
	}
	if evs := e.events(audit.SettingsBootRequest); len(evs) != 1 || !strings.Contains(string(evs[0].Details), `"ZANSKAR_LISTEN_ADDR":":443"`) {
		t.Fatalf("request audit: %+v", evs)
	}
	if !e.ctrl.Draining() {
		t.Fatal("not draining while the helper works")
	}
	res, _ := json.Marshal(bootedit.Result{ID: id, State: bootedit.Refused, Message: "the gateway would not start with it: no master key", At: time.Now()})
	if err := os.WriteFile(filepath.Join(dir, bootedit.ResultFile), res, 0o600); err != nil {
		t.Fatal(err)
	}
	e.waitFor(func() bool { return !e.ctrl.Draining() })
	if evs := e.events(audit.SettingsBootApply); len(evs) != 1 || evs[0].Outcome != audit.Failure || !strings.Contains(string(evs[0].Details), "no master key") {
		t.Fatalf("refusal audit: %+v", evs)
	}
	if code, out := e.do("GET", "/api/v1/admin/settings/boot/result", nil); code != 200 || out["state"] != bootedit.Refused || out["id"] != id {
		t.Fatalf("result route: %d %v", code, out)
	}
}

// TestAckConfigResult: after the helper restarted the gateway, the new
// process audits how the change ended, once, under the administrator who
// asked; a refusal was already audited by the process that saw it.
func TestAckConfigResult(t *testing.T) {
	e := newHostEnv(t)
	dir := t.TempDir()
	write := func(res bootedit.Result) {
		b, _ := json.Marshal(res)
		if err := os.WriteFile(filepath.Join(dir, bootedit.ResultFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	admin := strings.Repeat("a", 32)
	write(bootedit.Result{ID: "r1", RequestedBy: admin, State: bootedit.Applied, Changed: []string{"ZANSKAR_PUBLIC_URL"}, At: time.Now()})
	AckConfigResult(context.Background(), dir, e.auditLog)
	AckConfigResult(context.Background(), dir, e.auditLog)
	evs := e.events(audit.SettingsBootApply)
	if len(evs) != 1 || evs[0].Outcome != audit.Success || evs[0].ActorUserID != admin {
		t.Fatalf("applied audit: %+v", evs)
	}
	write(bootedit.Result{ID: "r2", RequestedBy: "not an id; DROP TABLE", State: bootedit.RolledBack, Message: "readyz never answered", At: time.Now()})
	AckConfigResult(context.Background(), dir, e.auditLog)
	evs = e.events(audit.SettingsBootApply)
	if len(evs) != 2 || evs[0].Outcome != audit.Failure || evs[0].ActorUserID != "" || !strings.Contains(fmt.Sprint(string(evs[0].Details)), "readyz") {
		t.Fatalf("rolled-back audit: %+v", evs)
	}
	write(bootedit.Result{ID: "r3", State: bootedit.Refused, At: time.Now()})
	AckConfigResult(context.Background(), dir, e.auditLog)
	if evs := e.events(audit.SettingsBootApply); len(evs) != 2 {
		t.Fatal("a refusal was audited twice")
	}
}
