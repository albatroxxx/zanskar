// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
)

// 2026-11-03, idea 11: each person sees their own activity: their sign-ins,
// failed ones too, their sessions, and what others did to their account and
// who. Never another person's events, nor another person's address.
func TestMyActivity(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	alice, root, reviewer := e.ids["alice"], e.ids["root"], e.ids["reviewer"]
	rec := func(ev audit.Event) {
		t.Helper()
		if _, err := e.audit.Record(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	rec(audit.Actor{UserID: alice, IP: "198.51.100.7"}.Event(audit.UserLogin, "user", alice, audit.Success, map[string]any{"method": "password"}))
	rec(audit.Actor{IP: "203.0.113.66"}.Event(audit.UserLogin, "user", alice, audit.Failure, map[string]any{"reason": "bad_password", "username": "alice"}))
	rec(audit.Actor{UserID: root, IP: "10.9.9.9"}.Event("user.roles.update", "user", alice, audit.Success, map[string]any{"roles": []string{"user"}, "secretish": "x"}))
	rec(audit.Actor{UserID: alice, IP: "198.51.100.7"}.Event(audit.SessionConnect, "target", "t1", audit.Success, nil))
	rec(audit.Actor{UserID: alice, IP: "198.51.100.7"}.Event(audit.AuditRead, "audit_log", "", audit.Success, nil))
	rec(audit.Actor{UserID: reviewer, IP: "10.1.1.1"}.Event(audit.UserLogin, "user", reviewer, audit.Success, nil))
	rec(audit.Actor{UserID: root, IP: "10.9.9.9"}.Event("user.roles.update", "user", reviewer, audit.Success, nil))

	rr, body := e.get("/api/v1/me/activity", "alice")
	if rr.Code != 200 {
		t.Fatalf("activity: %d %s", rr.Code, rr.Body)
	}
	items := body["items"].([]any)
	if len(items) != 3 {
		t.Fatalf("got %d events, want alice's sign-in, the failed one and root's change: %s", len(items), rr.Body)
	}
	byAction := func(i int) map[string]any { return items[i].(map[string]any) }
	// Newest first: root's change, the failed sign-in, the sign-in.
	change, failed, signin := byAction(0), byAction(1), byAction(2)
	if change["action"] != "user.roles.update" || change["by"] != "root" || change["ip"] != "" {
		t.Fatalf("an administrator's change: %v", change)
	}
	if d, _ := change["details"].(map[string]any); d != nil {
		t.Fatalf("details beyond the allowed keys leaked: %v", d)
	}
	if failed["outcome"] != "failure" || failed["by"] != "gateway" || failed["details"].(map[string]any)["reason"] != "bad_password" {
		t.Fatalf("a failed sign-in: %v", failed)
	}
	if signin["ip"] != "198.51.100.7" || signin["by"] != nil || signin["details"].(map[string]any)["method"] != "password" {
		t.Fatalf("the person's own sign-in: %v", signin)
	}

	// A failed attempt on the account keeps where it came from: its owner
	// needs that. An administrator's own address is not shown (above).
	if failed["ip"] != "203.0.113.66" {
		t.Fatalf("a failed sign-in's source: %v", failed)
	}

	// Every role has its own activity, the auditor too.
	if rr, _ := e.get("/api/v1/me/activity", "reviewer"); rr.Code != 200 {
		t.Fatalf("auditor: %d", rr.Code)
	}
	// Reading it records nothing.
	if evs, _, _ := e.audit.List(ctx, audit.Filter{Action: audit.AuditRead, ActorUserID: alice}); len(evs) != 1 {
		t.Fatalf("reading one's activity was audited: %d reads", len(evs))
	}
}
