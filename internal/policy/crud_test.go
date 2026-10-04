// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/user"
)

func (e *handlerEnv) lastEvent(t *testing.T, action string) audit.Event {
	t.Helper()
	evs, _, err := e.audit.List(context.Background(), audit.Filter{Action: action, Limit: 1})
	if err != nil || len(evs) == 0 {
		t.Fatalf("no %s event: %v", action, err)
	}
	return evs[0]
}

// TestPolicyLifecycle: an admin creates, reads, lists, replaces and deletes a
// policy, and each change is audited. An update replaces the whole policy, as
// the API spec says: a switch left out of the body takes its default, not its
// current value. A plain user cannot reach the policy routes.
func TestPolicyLifecycle(t *testing.T) {
	e := newHandlerEnv(t)
	g := e.createUser(t, "placeholder", user.RoleUser) // a user-scoped subject
	body := map[string]any{"name": "prod-ssh", "user_id": g.ID, "target_selector": map[string]any{"tags": map[string]string{"env": "prod"}},
		"protocols": []string{"ssh"}, "require_mfa": false, "allow_clipboard": true}

	code, out := e.do("POST", "/api/v1/access-policies", body)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("create: %d %v", code, out)
	}
	id, _ := out["id"].(string)
	if out["require_mfa"] != false || out["allow_clipboard"] != true {
		t.Fatalf("created switches: %v", out)
	}
	if ev := e.lastEvent(t, "policy.create"); ev.ObjectID != id {
		t.Fatalf("policy.create names %s, want %s", ev.ObjectID, id)
	}

	if code, out := e.do("GET", "/api/v1/access-policies/"+id, nil); code != http.StatusOK || out["name"] != "prod-ssh" {
		t.Fatalf("get: %d %v", code, out)
	}
	if code, out := e.do("GET", "/api/v1/access-policies", nil); code != http.StatusOK || len(out["items"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, out)
	}

	// Replace without the two switches: they fall back to their defaults.
	partial := map[string]any{"name": "prod-ssh", "user_id": g.ID, "target_selector": body["target_selector"], "protocols": []string{"ssh"}}
	code, out = e.do("PUT", "/api/v1/access-policies/"+id, partial)
	if code != http.StatusOK || out["require_mfa"] != true || out["allow_clipboard"] != false || out["enabled"] != true {
		t.Fatalf("update with switches left out: %d %v; want require_mfa on, clipboard off, enabled", code, out)
	}
	if ev := e.lastEvent(t, "policy.update"); ev.ObjectID != id {
		t.Fatalf("policy.update names %s", ev.ObjectID)
	}

	req := httptest.NewRequest("DELETE", "/api/v1/access-policies/"+id, nil)
	req.Header.Set("X-CSRF-Token", e.csrf)
	req.AddCookie(e.admin)
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body)
	}
	if ev := e.lastEvent(t, "policy.delete"); ev.ObjectID != id {
		t.Fatalf("policy.delete names %s", ev.ObjectID)
	}
	for _, m := range []string{"GET", "DELETE"} {
		if code, _ := e.do(m, "/api/v1/access-policies/"+id, nil); code != http.StatusNotFound {
			t.Errorf("%s a deleted policy: %d, want 404", m, code)
		}
	}

	// A plain user is refused every policy route.
	plain := e.createUser(t, "pat", user.RoleUser)
	tok, sess, err := e.sessions.Create(context.Background(), plain.ID, "203.0.113.7", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"GET", "POST"} {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(m, "/api/v1/access-policies", bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", e.sessions.CSRFToken(sess.ID))
		r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: tok})
		w := httptest.NewRecorder()
		e.srv.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("plain user %s policies: %d, want 403", m, w.Code)
		}
	}
}
