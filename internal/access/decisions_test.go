// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/user"
)

func (e *env) lastEvent(t *testing.T, action string) (audit.Event, map[string]any) {
	t.Helper()
	evs, _, err := e.audit.List(context.Background(), audit.Filter{Action: action, Limit: 1})
	if err != nil || len(evs) == 0 {
		t.Fatalf("no %s event: %v", action, err)
	}
	var d map[string]any
	_ = json.Unmarshal(evs[0].Details, &d)
	return evs[0], d
}

func (e *env) request(t *testing.T) string {
	t.Helper()
	code, out := e.do("POST", "/api/v1/me/access-requests", map[string]any{"target_id": e.target, "protocol": "ssh", "reason": "incident 7", "minutes": 30}, e.alice, e.aliceCSR)
	if code != http.StatusCreated {
		t.Fatalf("request: %d %v", code, out)
	}
	return out["id"].(string)
}

// TestRequestValidation: a request names a target, a protocol, a reason and
// a duration within the policy's maximum, and only an approval-gated policy
// of the requester's makes them eligible. An auditor-only account cannot
// request access at all (ADR 0006).
func TestRequestValidation(t *testing.T) {
	e := newEnv(t)
	ok := map[string]any{"target_id": e.target, "protocol": "ssh", "reason": "incident 7", "minutes": 30}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range ok {
			m[kk] = vv
		}
		m[k] = v
		return m
	}
	cases := []struct {
		name   string
		body   map[string]any
		status int
		code   string
	}{
		{"no target", with("target_id", ""), http.StatusBadRequest, "bad_request"},
		{"blank reason", with("reason", "   "), http.StatusBadRequest, "bad_request"},
		{"no duration", with("minutes", 0), http.StatusBadRequest, "bad_request"},
		{"longer than the policy allows", with("minutes", 121), http.StatusBadRequest, "duration_too_long"},
		{"unknown target", with("target_id", "no-such-target"), http.StatusNotFound, "not_found"},
		{"a protocol the policy does not cover", with("protocol", "rdp"), http.StatusForbidden, "not_eligible"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code, out := e.do("POST", "/api/v1/me/access-requests", c.body, e.alice, e.aliceCSR); code != c.status || out["code"] != c.code {
				t.Fatalf("got %d %v, want %d %s", code, out, c.status, c.code)
			}
		})
	}
	t.Run("an auditor cannot request access", func(t *testing.T) {
		cookie, csrf := e.login("reviewer", user.RoleAuditor)
		if code, _ := e.do("POST", "/api/v1/me/access-requests", ok, cookie, csrf); code != http.StatusForbidden {
			t.Fatalf("auditor request: %d, want 403", code)
		}
	})
	t.Run("a user without an approval-gated policy is not eligible", func(t *testing.T) {
		cookie, csrf := e.login("bob", user.RoleUser)
		if code, out := e.do("POST", "/api/v1/me/access-requests", ok, cookie, csrf); code != http.StatusForbidden || out["code"] != "not_eligible" {
			t.Fatalf("bob request: %d %v", code, out)
		}
	})
}

// TestDecisions: only an admin decides; each decision is audited with the
// admin as actor; a decided request cannot be decided again; an approved
// grant shows as the requester's active access until it is revoked; users
// see only their own requests, admins see all and can filter by status.
func TestDecisions(t *testing.T) {
	e := newEnv(t)
	bob, bobCSRF := e.login("bob", user.RoleUser)

	first := e.request(t)
	if code, out := e.do("GET", "/api/v1/me/access-requests", nil, e.alice, e.aliceCSR); code != http.StatusOK || len(out["items"].([]any)) != 1 {
		t.Fatalf("alice's requests: %d %v", code, out)
	}
	if _, out := e.do("GET", "/api/v1/me/access-requests", nil, bob, bobCSRF); len(out["items"].([]any)) != 0 {
		t.Fatalf("bob must not see alice's request: %v", out)
	}
	if _, out := e.do("GET", "/api/v1/access-requests?status=pending", nil, e.admin, e.adminCSR); len(out["items"].([]any)) != 1 {
		t.Fatalf("admin pending list: %v", out)
	}
	if code, _ := e.do("GET", "/api/v1/access-requests?status=maybe", nil, e.admin, e.adminCSR); code != http.StatusBadRequest {
		t.Fatalf("unknown status filter: %d, want 400", code)
	}
	for _, action := range []string{"approve", "deny", "revoke"} {
		if code, _ := e.do("POST", "/api/v1/access-requests/"+first+"/"+action, nil, e.alice, e.aliceCSR); code != http.StatusForbidden {
			t.Errorf("alice may not %s: got %d", action, code)
		}
	}
	if code, _ := e.do("GET", "/api/v1/access-requests", nil, e.alice, e.aliceCSR); code != http.StatusForbidden {
		t.Errorf("alice listing every request: %d, want 403", code)
	}

	// Deny, audited, final.
	if code, out := e.do("POST", "/api/v1/access-requests/"+first+"/deny", map[string]string{"note": "use the replica"}, e.admin, e.adminCSR); code != http.StatusOK || out["status"] != "denied" {
		t.Fatalf("deny: %d %v", code, out)
	}
	if ev, d := e.lastEvent(t, "access.request.deny"); ev.ActorUserID != e.ids["root"] || ev.ObjectID != first || d["status"] != "denied" {
		t.Fatalf("deny audit: actor %s object %s %v", ev.ActorUserID, ev.ObjectID, d)
	}
	for _, action := range []string{"approve", "deny"} {
		if code, _ := e.do("POST", "/api/v1/access-requests/"+first+"/"+action, nil, e.admin, e.adminCSR); code != http.StatusConflict {
			t.Errorf("%s a denied request: %d, want 409", action, code)
		}
	}

	// Approve, active, revoke, audited.
	second := e.request(t)
	if code, _ := e.do("POST", "/api/v1/access-requests/"+second+"/approve", map[string]int{"minutes": -5}, e.admin, e.adminCSR); code != http.StatusBadRequest {
		t.Fatalf("approve for negative minutes: %d, want 400", code)
	}
	if code, out := e.do("POST", "/api/v1/access-requests/"+second+"/approve", nil, e.admin, e.adminCSR); code != http.StatusOK || out["status"] != "approved" {
		t.Fatalf("approve: %d %v", code, out)
	}
	if _, out := e.do("GET", "/api/v1/me/access", nil, e.alice, e.aliceCSR); len(out["items"].([]any)) != 1 {
		t.Fatalf("alice's active access after approval: %v", out)
	}
	if code, out := e.do("POST", "/api/v1/access-requests/"+second+"/revoke", map[string]string{"note": "done"}, e.admin, e.adminCSR); code != http.StatusOK || out["status"] != "revoked" {
		t.Fatalf("revoke: %d %v", code, out)
	}
	if ev, _ := e.lastEvent(t, "access.request.revoke"); ev.ActorUserID != e.ids["root"] || ev.ObjectID != second {
		t.Fatalf("revoke audit: actor %s object %s", ev.ActorUserID, ev.ObjectID)
	}
	if _, out := e.do("GET", "/api/v1/me/access", nil, e.alice, e.aliceCSR); len(out["items"].([]any)) != 0 {
		t.Fatalf("alice still has access after revoke: %v", out)
	}
	if code, _ := e.do("POST", "/api/v1/access-requests/"+second+"/revoke", nil, e.admin, e.adminCSR); code != http.StatusConflict {
		t.Fatalf("revoke twice: %d, want 409", code)
	}
	if code, _ := e.do("POST", "/api/v1/access-requests/no-such-request/revoke", nil, e.admin, e.adminCSR); code != http.StatusNotFound {
		t.Fatalf("revoke unknown: %d, want 404", code)
	}
}
