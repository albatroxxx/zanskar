// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
)

// liveRevoker stands in for the gateway. It records whose live sessions it
// was asked to end and reports ended sessions for each such call; anything
// else it is asked is recorded as unexpected.
type liveRevoker struct {
	ended      int
	users      []string
	unexpected []string
}

func (f *liveRevoker) UserRevoked(userID string) int {
	f.users = append(f.users, userID)
	return f.ended
}

func (f *liveRevoker) PolicyDeleted(string) int {
	f.unexpected = append(f.unexpected, "PolicyDeleted")
	return 0
}

func (f *liveRevoker) PolicyChanged(context.Context, string) int {
	f.unexpected = append(f.unexpected, "PolicyChanged")
	return 0
}

func (f *liveRevoker) TargetDisabled(string) int {
	f.unexpected = append(f.unexpected, "TargetDisabled")
	return 0
}

func (f *liveRevoker) TargetTrustLost(string) int {
	f.unexpected = append(f.unexpected, "TargetTrustLost")
	return 0
}

func (f *liveRevoker) GrantRevoked(context.Context, string, string, string, string) int {
	f.unexpected = append(f.unexpected, "GrantRevoked")
	return 0
}

func (f *liveRevoker) GrantExpired(context.Context, string, string, string, string) int {
	f.unexpected = append(f.unexpected, "GrantExpired")
	return 0
}

func (f *liveRevoker) GroupMembersRemoved(context.Context, string, []string) int {
	f.unexpected = append(f.unexpected, "GroupMembersRemoved")
	return 0
}

func (f *liveRevoker) GroupDeleted(context.Context, string) int {
	f.unexpected = append(f.unexpected, "GroupDeleted")
	return 0
}

// TestAccountChangesEndLiveSessions: disabling or locking an account,
// changing its roles, signing it out everywhere, resetting its password or
// authenticator and deleting it each end the
// user's live sessions through the gateway, and the event for the change
// says how many ended. Edits that leave access alone (a new display name,
// re-enabling, the same roles in another order) end nothing.
func TestAccountChangesEndLiveSessions(t *testing.T) {
	e := newEnv(t)
	rv := &liveRevoker{ended: 2}
	e.h.Revoker = rv
	r := e.do("POST", "/api/v1/users", map[string]any{"username": "opal", "display_name": "Opal", "roles": []string{"user"}})
	if r.code != 201 {
		t.Fatalf("create: %d %v", r.code, r.body)
	}
	id := r.body["id"].(string)

	// ended reports the live_sessions_ended detail of the newest event for
	// action on the user, and whether it is there at all.
	ended := func(action string) (any, bool) {
		t.Helper()
		evs, _, err := e.audit.List(context.Background(), audit.Filter{Action: action, ObjectID: id, Limit: 1})
		if err != nil || len(evs) != 1 {
			t.Fatalf("no %s event: %v", action, err)
		}
		var d map[string]any
		_ = json.Unmarshal(evs[0].Details, &d)
		v, ok := d["live_sessions_ended"]
		return v, ok
	}
	step := func(name, method, path string, body any, wantCall bool, action string) {
		t.Helper()
		before := len(rv.users)
		if r := e.do(method, path, body); r.code != 200 && r.code != 204 {
			t.Fatalf("%s: %d %v", name, r.code, r.body)
		}
		called := len(rv.users) > before
		if called != wantCall || (called && (len(rv.users) != before+1 || rv.users[before] != id)) {
			t.Fatalf("%s: revoker calls %v (had %d), want a call for %s: %v", name, rv.users, before, id, wantCall)
		}
		v, ok := ended(action)
		if wantCall && v != float64(2) {
			t.Fatalf("%s: %s live_sessions_ended = %v, want 2", name, action, v)
		}
		if !wantCall && ok {
			t.Fatalf("%s: %s says live_sessions_ended = %v though nothing was revoked", name, action, v)
		}
	}

	step("rename", "PUT", "/api/v1/users/"+id, map[string]any{"display_name": "Opal R"}, false, "user.update")
	step("disable", "PUT", "/api/v1/users/"+id, map[string]any{"status": "disabled"}, true, "user.update")
	step("re-enable", "PUT", "/api/v1/users/"+id, map[string]any{"status": "active"}, false, "user.update")
	step("lock", "PUT", "/api/v1/users/"+id, map[string]any{"status": "locked"}, true, "user.update")
	step("add a role", "PUT", "/api/v1/users/"+id+"/roles", map[string]any{"roles": []string{"user", "auditor"}}, true, "user.roles.update")
	step("same roles reordered", "PUT", "/api/v1/users/"+id+"/roles", map[string]any{"roles": []string{"auditor", "user"}}, false, "user.roles.update")
	step("drop a role", "PUT", "/api/v1/users/"+id+"/roles", map[string]any{"roles": []string{"auditor"}}, true, "user.roles.update")
	step("sign out everywhere", "DELETE", "/api/v1/users/"+id+"/sessions", nil, true, "user.sessions.revoke")
	// Both resets already sign the user out of the console; their live
	// sessions end with it.
	step("password reset", "PUT", "/api/v1/users/"+id+"/password", map[string]any{"generate": true}, true, "user.password.reset")
	step("authenticator reset", "DELETE", "/api/v1/users/"+id+"/mfa", nil, true, "user.mfa.reset")
	step("delete", "DELETE", "/api/v1/users/"+id, nil, true, "user.delete")

	if len(rv.unexpected) != 0 {
		t.Fatalf("unexpected revoker calls: %v", rv.unexpected)
	}
	// A refused change revokes nothing.
	before := slices.Clone(rv.users)
	if r := e.do("PUT", "/api/v1/users/"+e.admin.ID, map[string]any{"status": "disabled"}); r.code != 409 {
		t.Fatalf("self disable: %d %v", r.code, r.body)
	}
	if r := e.do("DELETE", "/api/v1/users/no-such-user", nil); r.code != 404 {
		t.Fatalf("unknown user: %d %v", r.code, r.body)
	}
	if !slices.Equal(rv.users, before) {
		t.Fatalf("refused changes revoked %v", rv.users[len(before):])
	}
}
