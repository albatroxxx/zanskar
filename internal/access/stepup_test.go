// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"errors"
	"testing"

	"github.com/albatroxxx/zanskar/internal/user"
)

// 2026-11-03, idea 3: a notification links to the request, never to a token
// that approves it (ADR 0039); approving asks an approver who has an
// authenticator for a recent code, so a stolen session or a forwarded link
// alone cannot grant access.

// pendingRequest has alice ask for the target and returns the request id.
func pendingRequest(t *testing.T, e *env) string {
	t.Helper()
	code, out := e.do("POST", "/api/v1/me/access-requests", map[string]any{"target_id": e.target, "protocol": "ssh", "reason": "deploy", "minutes": 30}, e.alice, e.aliceCSR)
	if code != 201 {
		t.Fatalf("request: %d %v", code, out)
	}
	return out["id"].(string)
}

func TestApprovingAsksAnApproverWithAnAuthenticatorForARecentCode(t *testing.T) {
	e := newEnv(t)
	on := true
	e.h.ApproveStepUp = func() bool { return on }
	enrolled := map[string]bool{e.ids["root"]: true}
	e.h.MFAEnrolled = func(_ context.Context, id string) (bool, error) { return enrolled[id], nil }
	id := pendingRequest(t, e)

	code, out := e.do("POST", "/api/v1/access-requests/"+id+"/approve", nil, e.admin, e.adminCSR)
	if code != 403 || out["code"] != "step_up_required" {
		t.Fatalf("approve without a recent code: %d %v, want 403 step_up_required", code, out)
	}
	if r, _ := e.requests.Get(context.Background(), id); r.Status != StatusPending {
		t.Fatalf("a refused approval leaves the request pending, got %s", r.Status)
	}
	// Denying takes access away and never asks.
	other := pendingRequestFor(t, e, e.group)
	if code, out := e.do("POST", "/api/v1/access-requests/"+other+"/deny", nil, e.admin, e.adminCSR); code != 200 {
		t.Fatalf("deny without a code: %d %v", code, out)
	}
	if err := e.sessions.MarkMFAProved(context.Background(), e.sessIDs["root"]); err != nil {
		t.Fatal(err)
	}
	if code, out := e.do("POST", "/api/v1/access-requests/"+id+"/approve", nil, e.admin, e.adminCSR); code != 200 || out["status"] != string(StatusApproved) {
		t.Fatalf("approve with a recent code: %d %v", code, out)
	}
	// Revoking never asks either (the code is fresh here, so check with a
	// second approver who never proved one).
	bob, bobCSRF := e.login("bob", user.RoleAdmin)
	enrolled[e.ids["bob"]] = true
	if code, out := e.do("POST", "/api/v1/access-requests/"+id+"/revoke", nil, bob, bobCSRF); code != 200 {
		t.Fatalf("revoke without a code: %d %v", code, out)
	}
}

func TestAnApproverWithoutAnAuthenticatorIsNotAsked(t *testing.T) {
	e := newEnv(t)
	e.h.ApproveStepUp = func() bool { return true }
	e.h.MFAEnrolled = func(context.Context, string) (bool, error) { return false, nil }
	id := pendingRequest(t, e)
	if code, out := e.do("POST", "/api/v1/access-requests/"+id+"/approve", nil, e.admin, e.adminCSR); code != 200 {
		t.Fatalf("single sign-on approver, proved by the provider: %d %v", code, out)
	}
}

func TestTheSettingOffAsksNothing(t *testing.T) {
	e := newEnv(t)
	e.h.ApproveStepUp = func() bool { return false }
	e.h.MFAEnrolled = func(context.Context, string) (bool, error) { return true, nil }
	id := pendingRequest(t, e)
	if code, out := e.do("POST", "/api/v1/access-requests/"+id+"/approve", nil, e.admin, e.adminCSR); code != 200 {
		t.Fatalf("setting off: %d %v", code, out)
	}
}

func TestUnknownEnrolmentAsksOrFails(t *testing.T) {
	e := newEnv(t)
	e.h.ApproveStepUp = func() bool { return true }
	id := pendingRequest(t, e)
	// No way to tell whether the approver has an authenticator: asked.
	if code, out := e.do("POST", "/api/v1/access-requests/"+id+"/approve", nil, e.admin, e.adminCSR); code != 403 || out["code"] != "step_up_required" {
		t.Fatalf("enrolment unknown: %d %v, want the code asked", code, out)
	}
	// A failed lookup refuses, never approves.
	e.h.MFAEnrolled = func(context.Context, string) (bool, error) { return false, errors.New("database gone") }
	if code, _ := e.do("POST", "/api/v1/access-requests/"+id+"/approve", nil, e.admin, e.adminCSR); code != 500 {
		t.Fatalf("enrolment lookup failed: %d, want 500", code)
	}
	if r, _ := e.requests.Get(context.Background(), id); r.Status != StatusPending {
		t.Fatalf("still pending, got %s", r.Status)
	}
}

func TestADecidedRequestSaysSoBeforeAnyCode(t *testing.T) {
	e := newEnv(t)
	id := pendingRequest(t, e)
	if code, _ := e.do("POST", "/api/v1/access-requests/"+id+"/deny", nil, e.admin, e.adminCSR); code != 200 {
		t.Fatal("deny")
	}
	e.h.ApproveStepUp = func() bool { return true }
	e.h.MFAEnrolled = func(context.Context, string) (bool, error) { return true, nil }
	if code, out := e.do("POST", "/api/v1/access-requests/"+id+"/approve", nil, e.admin, e.adminCSR); code != 409 {
		t.Fatalf("an old link to a decided request: %d %v, want 409 before any code", code, out)
	}
}

func TestOneRequestOpensForAnAdminOnly(t *testing.T) {
	e := newEnv(t)
	id := pendingRequest(t, e)
	code, out := e.do("GET", "/api/v1/access-requests/"+id, nil, e.admin, e.adminCSR)
	if code != 200 || out["id"] != id || out["username"] != "alice" || out["target_name"] != "web-1" || out["status"] != string(StatusPending) {
		t.Fatalf("one request: %d %v", code, out)
	}
	if code, _ := e.do("GET", "/api/v1/access-requests/"+id, nil, e.alice, e.aliceCSR); code != 403 {
		t.Fatalf("the requester reads her own through /me, not this: %d", code)
	}
	rita, ritaCSRF := e.login("rita", user.RoleAuditor)
	if code, _ := e.do("GET", "/api/v1/access-requests/"+id, nil, rita, ritaCSRF); code != 403 {
		t.Fatalf("an auditor: %d, want 403", code)
	}
	if code, _ := e.do("GET", "/api/v1/access-requests/00000000000000000000000000000000", nil, e.admin, e.adminCSR); code != 404 {
		t.Fatalf("unknown: %d, want 404", code)
	}
}

// pendingRequestFor has alice ask for an autoscaling group.
func pendingRequestFor(t *testing.T, e *env, asgID string) string {
	t.Helper()
	code, out := e.do("POST", "/api/v1/me/access-requests", map[string]any{"asg_id": asgID, "protocol": "ssh", "reason": "deploy", "minutes": 30}, e.alice, e.aliceCSR)
	if code != 201 {
		t.Fatalf("request for the group: %d %v", code, out)
	}
	return out["id"].(string)
}
