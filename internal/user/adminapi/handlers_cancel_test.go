// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/user"
)

// cancelOnRevoke stands in for the session store and cancels the request's
// context the moment the revoke lands: what net/http does when the client
// hangs up between the mutation and the audit insert.
type cancelOnRevoke struct {
	cancel context.CancelFunc
	calls  int
}

func (c *cancelOnRevoke) RevokeAllForUser(context.Context, string) (int64, error) {
	c.calls++
	c.cancel()
	return 1, nil
}

// TestAuditSurvivesClientDisconnect: a mutation whose client disconnected
// after the write but before the audit row must still be audited (H7).
func TestAuditSurvivesClientDisconnect(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	revoker := &cancelOnRevoke{cancel: cancel}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &AdminHandler{Users: e.users, Sessions: revoker, TOTP: e.totp, Audit: e.audit, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: e.sessions, Users: e.users, Log: log}
	srv := mw.Authenticate(mw.CSRF(mux))

	alice := &user.User{Username: "alice", DisplayName: "Alice", Roles: []user.Role{user.RoleUser}}
	if err := e.users.Create(context.Background(), alice); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("DELETE", "/api/v1/users/"+alice.ID+"/sessions", nil).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrf)
	req.RemoteAddr = "127.0.0.1:1"
	req.AddCookie(e.cookie)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rr.Code, rr.Body.String())
	}
	if revoker.calls != 1 || ctx.Err() == nil {
		t.Fatalf("test setup: revoke ran %d times, context err %v; the audit must run after the cancel", revoker.calls, ctx.Err())
	}
	events, _, err := e.audit.List(context.Background(), audit.Filter{Action: "user.sessions.revoke", ObjectID: alice.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("want the revoke audited once despite the disconnect, got %d rows", len(events))
	}
	if events[0].ActorUserID != e.admin.ID || events[0].ActorIP != "127.0.0.1" {
		t.Fatalf("actor = %q@%q, want admin %q@127.0.0.1", events[0].ActorUserID, events[0].ActorIP, e.admin.ID)
	}
}
