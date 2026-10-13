// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// liveRevoker stands in for the gateway. It records which policies it was
// told changed or went, and reports ended sessions for each such call;
// anything else it is asked is recorded as unexpected.
type liveRevoker struct {
	ended      int
	changed    []string
	deleted    []string
	unexpected []string
}

func (f *liveRevoker) UserRevoked(string) int {
	f.unexpected = append(f.unexpected, "UserRevoked")
	return 0
}

func (f *liveRevoker) PolicyDeleted(policyID string) int {
	f.deleted = append(f.deleted, policyID)
	return f.ended
}

func (f *liveRevoker) PolicyChanged(_ context.Context, policyID string) int {
	f.changed = append(f.changed, policyID)
	return f.ended
}

func (f *liveRevoker) GroupMembersRemoved(context.Context, string, []string) int {
	f.unexpected = append(f.unexpected, "GroupMembersRemoved")
	return 0
}

func (f *liveRevoker) GroupDeleted(context.Context, string) int {
	f.unexpected = append(f.unexpected, "GroupDeleted")
	return 0
}

// TestPolicyChangesEndLiveSessions: once an update is stored the gateway is
// told the policy changed, and once a delete is, that it went; each event
// says how many live sessions ended. Creating a policy only adds access, and
// a refused update or delete is not passed on.
func TestPolicyChangesEndLiveSessions(t *testing.T) {
	e := newHandlerEnv(t)
	rv := &liveRevoker{ended: 4}
	e.h.Revoker = rv
	u := e.createUser(t, "operator", user.RoleUser)
	body := map[string]any{"name": "prod-ssh", "user_id": u.ID, "target_selector": map[string]any{"tags": map[string]string{"env": "prod"}},
		"protocols": []string{"ssh", "rdp"}}
	code, out := e.do("POST", "/api/v1/access-policies", body)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, out)
	}
	id := out["id"].(string)
	ended := func(action string) any {
		t.Helper()
		var d map[string]any
		_ = json.Unmarshal(e.lastEvent(t, action).Details, &d)
		return d["live_sessions_ended"]
	}
	if len(rv.changed)+len(rv.deleted) != 0 || ended("policy.create") != nil {
		t.Fatalf("create told the gateway %v / %v", rv.changed, rv.deleted)
	}

	body["protocols"] = []string{"ssh"}
	if code, out := e.do("PUT", "/api/v1/access-policies/"+id, body); code != http.StatusOK {
		t.Fatalf("update: %d %v", code, out)
	}
	if !slices.Equal(rv.changed, []string{id}) || ended("policy.update") != float64(4) {
		t.Fatalf("after update: changed %v, policy.update live_sessions_ended %v; want [%s] and 4", rv.changed, ended("policy.update"), id)
	}

	// Refused: an invalid body, an unknown policy.
	if code, _ := e.do("PUT", "/api/v1/access-policies/"+id, map[string]any{"name": "prod-ssh", "user_id": u.ID}); code != http.StatusBadRequest {
		t.Fatalf("invalid update: %d, want 400", code)
	}
	if code, _ := e.do("PUT", "/api/v1/access-policies/nope", body); code != http.StatusNotFound {
		t.Fatalf("update unknown: %d, want 404", code)
	}
	if code, _ := e.do("DELETE", "/api/v1/access-policies/nope", nil); code != http.StatusNotFound {
		t.Fatalf("delete unknown: %d, want 404", code)
	}
	if len(rv.changed) != 1 || len(rv.deleted) != 0 {
		t.Fatalf("refused changes reached the gateway: changed %v, deleted %v", rv.changed, rv.deleted)
	}

	if code, out := e.do("DELETE", "/api/v1/access-policies/"+id, nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d %v", code, out)
	}
	if !slices.Equal(rv.deleted, []string{id}) || ended("policy.delete") != float64(4) {
		t.Fatalf("after delete: deleted %v, policy.delete live_sessions_ended %v; want [%s] and 4", rv.deleted, ended("policy.delete"), id)
	}
	if len(rv.unexpected) != 0 {
		t.Fatalf("unexpected revoker calls: %v", rv.unexpected)
	}
}

// TestForGroup: ForGroup lists every policy bound to a group, enabled or
// not, in name order, and none bound to another group or to a user.
func TestForGroup(t *testing.T) {
	e := newHandlerEnv(t)
	ctx := context.Background()
	now := store.TimeArg(time.Now())
	for _, g := range []string{"g1", "g2"} {
		if _, err := e.db.ExecContext(ctx, e.db.Rebind(`INSERT INTO groups (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)`), g, g, now, now); err != nil {
			t.Fatal(err)
		}
	}
	u := e.createUser(t, "solo", user.RoleUser)
	repo := NewRepo(e.db)
	mk := func(name, groupID, userID string, enabled bool) string {
		t.Helper()
		p := &Policy{Name: name, GroupID: groupID, UserID: userID, Enabled: enabled, IdleTimeoutMinutes: 15,
			Selector: Selector{Tags: map[string]string{"env": "prod"}}, Protocols: []string{"ssh"}}
		if err := repo.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
		return p.ID
	}
	web, off := mk("web", "g1", "", true), mk("archive", "g1", "", false)
	mk("other-group", "g2", "", true)
	mk("solo", "", u.ID, true)

	got, err := repo.ForGroup(ctx, "g1")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, p := range got {
		ids = append(ids, p.ID)
	}
	if !slices.Equal(ids, []string{off, web}) {
		t.Fatalf("ForGroup(g1) = %v, want [archive web] = [%s %s]", ids, off, web)
	}
	if got, err := repo.ForGroup(ctx, "nope"); err != nil || len(got) != 0 {
		t.Fatalf("ForGroup(nope) = %v %v, want none", got, err)
	}
}
