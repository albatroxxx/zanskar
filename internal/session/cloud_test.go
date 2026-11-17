// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/gateway"
)

// A live cloud session's console end (ADR 0050, 3) is what a terminate
// cannot take back: the registry holds it beside the session, and the
// session's detail says it; a session without an issued console, or one
// this gateway does not hold, says nothing.
func TestSessionCarriesCloudConsoleUntil(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.h.Registry = gateway.NewRegistry()
	live := &Session{UserID: e.ids["alice"], TargetID: "t1", Protocol: "cloud", ClientIP: "10.0.0.1"}
	quiet := &Session{UserID: e.ids["alice"], TargetID: "t1", Protocol: "cloud", ClientIP: "10.0.0.1"}
	for _, s := range []*Session{live, quiet} {
		if err := e.repo.Start(ctx, s); err != nil {
			t.Fatal(err)
		}
		e.h.Registry.Add(ctx, gateway.Live{SessionID: s.ID, UserID: s.UserID, TargetID: "t1", Protocol: "cloud", Cloud: &gateway.CloudTerms{Console: true, CLI: true}})
	}
	t.Cleanup(func() {
		e.h.Registry.Remove(live.ID)
		e.h.Registry.Remove(quiet.ID)
	})
	until := time.Now().Add(45 * time.Minute).UTC().Truncate(time.Second)
	e.h.Registry.SetCloudConsoleUntil(live.ID, until)

	rr, out := e.get("/api/v1/sessions/"+live.ID, "root")
	if rr.Code != 200 {
		t.Fatalf("get: %d %s", rr.Code, rr.Body)
	}
	got, _ := out["cloud_console_until"].(string)
	parsed, err := time.Parse(time.RFC3339Nano, got)
	if err != nil || !parsed.Equal(until) {
		t.Fatalf("cloud_console_until %q, want %v (%v)", got, until, err)
	}
	if out["protocol"] != "cloud" || out["state"] != "live" {
		t.Fatalf("session: %v", out)
	}
	if _, out := e.get("/api/v1/sessions/"+quiet.ID, "root"); out["cloud_console_until"] != nil {
		t.Fatalf("a session without a console says one: %v", out["cloud_console_until"])
	}
	// Once the registry lets the session go, the detail says nothing: the
	// console's end is known while the gateway holds the session.
	e.h.Registry.Remove(live.ID)
	if _, out := e.get("/api/v1/sessions/"+live.ID, "root"); out["cloud_console_until"] != nil {
		t.Fatalf("a released session says a console end: %v", out["cloud_console_until"])
	}
}
