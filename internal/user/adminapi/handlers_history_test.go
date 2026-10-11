// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestDeleteKeepsAnAccountWithHistory: an account that ever opened a session
// is kept for the record (its sessions and recording views name it), so
// deleting it is refused up front with what to do instead, before anything
// is revoked or ended; an account with no history is deleted.
func TestDeleteKeepsAnAccountWithHistory(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	rv := &liveRevoker{}
	e.h.Revoker = rv
	used := &user.User{Username: "used", DisplayName: "Used", Roles: []user.Role{user.RoleUser}}
	if err := e.users.Create(ctx, used); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.sessions.Create(ctx, used.ID, "127.0.0.1", "test", true); err != nil {
		t.Fatal(err)
	}
	// One ended session on a target that no longer exists, as history is.
	for _, q := range []string{`PRAGMA foreign_keys = OFF`,
		`INSERT INTO access_sessions (id, user_id, target_id, protocol, client_ip, started_at) VALUES ('s1', '` + used.ID + `', 'gone', 'ssh', '10.0.0.1', '` + store.TimeArg(time.Now()) + `')`,
		`PRAGMA foreign_keys = ON`} {
		if _, err := e.db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}

	r := e.do("DELETE", "/api/v1/users/"+used.ID, nil)
	if r.code != 409 || r.body["code"] != "has_history" {
		t.Fatalf("delete of an account with history: %d %v", r.code, r.body)
	}
	if _, err := e.users.GetByID(ctx, used.ID); err != nil {
		t.Fatalf("the account is gone: %v", err)
	}
	if n, _ := e.sessions.RevokeAllForUser(ctx, used.ID); n != 1 || len(rv.users) != 0 {
		t.Fatalf("a refused delete revoked or ended something: browser sessions left %d, live ended %v", n, rv.users)
	}

	fresh := &user.User{Username: "fresh", DisplayName: "Fresh", Roles: []user.Role{user.RoleUser}}
	if err := e.users.Create(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if r := e.do("DELETE", "/api/v1/users/"+fresh.ID, nil); r.code != 204 {
		t.Fatalf("delete of an account with no history: %d %v", r.code, r.body)
	}
}
