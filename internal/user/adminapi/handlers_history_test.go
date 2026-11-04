// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestDeleteAnAccountWithHistory: an account that opened sessions is deleted
// like any other, its sign-ins revoked and its live sessions ended, and the
// sessions it opened stay in the record under the name it had (ADR 0046).
func TestDeleteAnAccountWithHistory(t *testing.T) {
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
		`INSERT INTO access_sessions (id, user_id, user_username, user_display_name, target_id, protocol, client_ip, started_at) VALUES ('s1', '` + used.ID + `', 'used', 'Used', 'gone', 'ssh', '10.0.0.1', '` + store.TimeArg(time.Now()) + `')`,
		`PRAGMA foreign_keys = ON`} {
		if _, err := e.db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}

	r := e.do("DELETE", "/api/v1/users/"+used.ID, nil)
	if r.code != 204 {
		t.Fatalf("delete of an account with history: %d %v", r.code, r.body)
	}
	if _, err := e.users.GetByID(ctx, used.ID); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("the account is still there: %v", err)
	}
	if len(rv.users) != 1 || rv.users[0] != used.ID {
		t.Fatalf("the delete must end the live sessions: %v", rv.users)
	}
	if n, _ := e.sessions.RevokeAllForUser(ctx, used.ID); n != 0 {
		t.Fatalf("browser sign-ins left after the delete: %d", n)
	}
	var who, id string
	if err := e.db.QueryRowContext(ctx, `SELECT user_id, user_username FROM access_sessions WHERE id = 's1'`).Scan(&id, &who); err != nil || id != used.ID || who != "used" {
		t.Fatalf("the session after the delete: %q %q %v", id, who, err)
	}
}
