// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/target"
)

// TestDatabaseSessionCap: with as many database sessions running as the cap
// allows, redeeming a database ticket is refused with 503 too_many_sessions
// before any container starts, and the refusal is audited like every other
// refused connect. Sessions of other protocols do not count, and a cap of 0
// is no cap: both let the request through to the WebSocket upgrade, which a
// plain GET cannot complete (426), so no container is ever started.
func TestDatabaseSessionCap(t *testing.T) {
	f := newConnectFixture(t)
	f.h.Registry = gateway.NewRegistry()
	f.h.DockerPath = "/nonexistent/docker"
	cred := &credential.Credential{Name: "pg", Type: credential.TypePassword, Mode: credential.ModeVaulted, Username: "postgres"}
	if err := f.h.Vault.Create(f.ctx, cred, &credential.Secret{Password: "pw-for-the-sidecar"}, f.alice.ID); err != nil {
		t.Fatal(err)
	}
	tg := &target.Target{Name: "orders", Address: "10.0.0.12", OSFamily: target.Linux, Engine: "postgres", DatabaseName: "app",
		TLSMode: "disable", Tags: map[string]string{"env": "test"},
		Ports: map[target.Protocol]int{target.Database: 5432}, Credentials: map[target.Protocol]string{target.Database: cred.ID}}
	if err := f.h.Targets.Create(f.ctx, tg); err != nil {
		t.Fatal(err)
	}
	redeem := func() (int, map[string]any) {
		t.Helper()
		code, out := f.connect(t, map[string]any{"target_id": tg.ID, "protocol": "database"})
		tok, _ := out["ticket"].(string)
		if code != http.StatusOK || tok == "" {
			t.Fatalf("connect: %d %v", code, out)
		}
		rr := f.do("GET", "/ws/database?cols=80&rows=24&ticket="+tok, "", nil, f.cookie, f.csrf)
		var body map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
		return rr.Code, body
	}

	f.h.DBMaxSessions = 2
	for _, id := range []string{"db-a", "db-b"} {
		f.h.Registry.Add(f.ctx, gateway.Live{SessionID: id, UserID: "someone", TargetID: "t", Protocol: "database"})
	}
	f.h.Registry.Add(f.ctx, gateway.Live{SessionID: "ssh-a", UserID: "someone", TargetID: "t", Protocol: "ssh"})
	code, body := redeem()
	if code != http.StatusServiceUnavailable || body["code"] != "too_many_sessions" {
		t.Fatalf("at the cap: %d %v", code, body)
	}
	ev := lastEvent(t, f, "session.connect")
	var d map[string]any
	_ = json.Unmarshal(ev.Details, &d)
	if ev.Outcome != audit.Failure || ev.ObjectID != tg.ID || d["reason"] != "too_many_sessions" || d["protocol"] != "database" || d["limit"] != float64(2) {
		t.Fatalf("refusal audited as %+v %v", ev, d)
	}

	// One database session below the cap: the ssh session does not count.
	f.h.Registry.Remove("db-b")
	if code, body := redeem(); code != http.StatusUpgradeRequired || body["code"] == "too_many_sessions" {
		t.Fatalf("below the cap: %d %v", code, body)
	}
	// No cap at all.
	f.h.Registry.Add(f.ctx, gateway.Live{SessionID: "db-b", UserID: "someone", TargetID: "t", Protocol: "database"})
	f.h.DBMaxSessions = 0
	if code, body := redeem(); code != http.StatusUpgradeRequired || body["code"] == "too_many_sessions" {
		t.Fatalf("with no cap: %d %v", code, body)
	}
}
