// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"testing"

	"github.com/albatroxxx/zanskar/internal/asg"
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/target"
)

// TestFailoverRefusals: failing over is a user's choice, and only for an
// autoscaling session whose instance was lost. An unknown session, a
// static-target session, one that ended for another reason, an instance of
// another group and an empty pool are each refused; a still-open session on
// an instance that has turned unhealthy is closed as lost and moved.
func TestFailoverRefusals(t *testing.T) {
	e := newASGEnv(t)
	ctx := context.Background()
	inst := func(id, health string, groupID string) *asg.Instance {
		t.Helper()
		in, _, err := e.asgs.UpsertInstance(ctx, &asg.Instance{GroupID: groupID, InstanceID: id, PrivateIP: "10.0.0.9", AvailabilityZone: "az-1",
			LifecycleState: "InService", ProbeHealth: health, HostKeyFingerprint: "SHA256:" + id, HostKeySource: "console"})
		if err != nil {
			t.Fatal(err)
		}
		return in
	}
	start := func(s *session.Session) *session.Session {
		t.Helper()
		s.UserID, s.Protocol, s.ClientIP = e.user.ID, "ssh", "203.0.113.5"
		if err := e.sessions.Start(ctx, s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	failover := func(id string, body map[string]any) (int, map[string]any) {
		return e.do("POST", "/api/v1/sessions/"+id+"/failover", body)
	}

	if code, _ := failover("no-such-session", nil); code != 404 {
		t.Errorf("unknown session: %d, want 404", code)
	}
	tg := &target.Target{Name: "plain", Address: "10.0.0.20", OSFamily: target.Linux}
	if err := e.h.Targets.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	static := start(&session.Session{TargetID: tg.ID})
	if code, out := failover(static.ID, nil); code != 409 || out["code"] != "not_failoverable" {
		t.Errorf("non-autoscaling session: %d %v", code, out)
	}

	a := inst("i-a", "healthy", e.group.ID)
	quit := start(&session.Session{ASGID: e.group.ID, ASGInstanceID: a.ID})
	if err := e.sessions.End(ctx, quit.ID, session.EndUserExit); err != nil {
		t.Fatal(err)
	}
	if code, out := failover(quit.ID, nil); code != 409 || out["code"] != "not_failoverable" {
		t.Errorf("a session the user ended: %d %v", code, out)
	}

	// Lost, but the only other instances are unhealthy or elsewhere.
	lost := start(&session.Session{ASGID: e.group.ID, ASGInstanceID: a.ID})
	if err := e.sessions.End(ctx, lost.ID, session.EndTargetLost); err != nil {
		t.Fatal(err)
	}
	inst("i-a", "unhealthy", e.group.ID)
	if code, out := failover(lost.ID, nil); code != 409 || out["code"] != "no_healthy_instances" {
		t.Errorf("empty pool: %d %v", code, out)
	}
	if code, out := failover(lost.ID, map[string]any{"asg_instance_id": "no-such-instance"}); code != 404 {
		t.Errorf("unknown instance: %d %v", code, out)
	}

	// Still open on an instance that has gone unhealthy: closed as lost,
	// then moved to a healthy one.
	b := inst("i-b", "healthy", e.group.ID)
	open := start(&session.Session{ASGID: e.group.ID, ASGInstanceID: a.ID})
	code, out := failover(open.ID, map[string]any{"asg_instance_id": b.ID})
	if code != 200 || out["asg_instance_id"] != b.ID {
		t.Fatalf("failover of an open session on a lost instance: %d %v", code, out)
	}
	if got, _ := e.sessions.Get(ctx, open.ID); got.EndedAt == nil || got.EndReason != session.EndTargetLost {
		t.Fatalf("the old session must be closed as lost: %+v", got)
	}
	evs, _, _ := e.h.Audit.List(ctx, audit.Filter{Action: "session.failover", Limit: 1})
	if len(evs) != 1 || evs[0].ObjectID != open.ID || evs[0].Outcome != audit.Success {
		t.Fatalf("session.failover audit: %+v", evs)
	}
}
