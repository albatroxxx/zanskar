// SPDX-License-Identifier: Apache-2.0

package group

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// liveRevoker stands in for the gateway. It records what it was asked to end
// and reports ended sessions for each call; for a deletion it also notes how
// many policies were still bound to the group when it was asked, since they
// go with the row.
type liveRevoker struct {
	db         *store.DB
	ended      int
	removed    map[string][]string // group id -> user ids
	deleted    []string
	boundThen  []int // policies bound to the group at each GroupDeleted
	unexpected []string
}

func (f *liveRevoker) UserRevoked(string) int {
	f.unexpected = append(f.unexpected, "UserRevoked")
	return 0
}

func (f *liveRevoker) PolicyDeleted(string) int {
	f.unexpected = append(f.unexpected, "PolicyDeleted")
	return 0
}

func (f *liveRevoker) PolicyChanged(context.Context, string) int {
	f.unexpected = append(f.unexpected, "PolicyChanged")
	return 0
}

func (f *liveRevoker) GroupMembersRemoved(_ context.Context, groupID string, userIDs []string) int {
	f.removed[groupID] = append(f.removed[groupID], userIDs...)
	return f.ended
}

func (f *liveRevoker) GroupDeleted(ctx context.Context, groupID string) int {
	n := -1
	_ = f.db.QueryRowContext(ctx, f.db.Rebind(`SELECT COUNT(*) FROM access_policies WHERE group_id = ?`), groupID).Scan(&n)
	f.deleted = append(f.deleted, groupID)
	f.boundThen = append(f.boundThen, n)
	return f.ended
}

// TestGroupChangesEndLiveSessions: taking members out of a group ends their
// live sessions under the group's policies, and deleting the group ends the
// sessions of every policy bound to it, asked while those policies exist.
// Each event says how many sessions ended; the deletion also names the
// policies that went with the group, which leave no trace of their own.
func TestGroupChangesEndLiveSessions(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{3}, 32), false)
	auditLog := audit.NewLog(db)
	groups := NewRepo(db)
	rv := &liveRevoker{db: db, ended: 3, removed: map[string][]string{}}
	h := &AdminHandler{Groups: groups, Revoker: rv, Audit: auditLog, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	srv := mw.Authenticate(mw.CSRF(mux))

	admin := &user.User{Username: "root", DisplayName: "Root", Roles: []user.Role{user.RoleAdmin}}
	if err := users.Create(ctx, admin); err != nil {
		t.Fatal(err)
	}
	token, sess, _ := sessions.Create(ctx, admin.ID, "127.0.0.1", "t", true)
	do := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", sessions.CSRFToken(sess.ID))
		req.RemoteAddr = "127.0.0.1:1"
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}
	details := func(action, groupID string) map[string]any {
		t.Helper()
		evs, _, err := auditLog.List(ctx, audit.Filter{Action: action, ObjectID: groupID, Limit: 1})
		if err != nil || len(evs) != 1 {
			t.Fatalf("no %s event: %v", action, err)
		}
		var d map[string]any
		_ = json.Unmarshal(evs[0].Details, &d)
		return d
	}

	a, b := mkUser(t, users, "ann"), mkUser(t, users, "ben")
	code, out := do("POST", "/api/v1/groups", map[string]any{"name": "ops"})
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	id := out["id"].(string)
	if code, out := do("PUT", "/api/v1/groups/"+id+"/members", map[string]any{"user_ids": []string{a.ID, b.ID}}); code != 200 {
		t.Fatalf("add members: %d %v", code, out)
	}
	if len(rv.removed) != 0 {
		t.Fatalf("adding members revoked %v", rv.removed)
	}
	if _, ok := details("group.members.update", id)["live_sessions_ended"]; ok {
		t.Fatal("adding members claims live sessions ended")
	}

	if code, out := do("PUT", "/api/v1/groups/"+id+"/members", map[string]any{"user_ids": []string{b.ID}}); code != 200 {
		t.Fatalf("remove a member: %d %v", code, out)
	}
	if got := rv.removed[id]; !slices.Equal(got, []string{a.ID}) {
		t.Fatalf("revoker told to end sessions of %v in %s, want [%s]", rv.removed, id, a.ID)
	}
	if d := details("group.members.update", id); d["live_sessions_ended"] != float64(3) {
		t.Fatalf("group.members.update details %v, want live_sessions_ended 3", d)
	}

	// Two policies bound to the group, one bound to a user: deleting the group
	// takes the first two with it.
	now := store.TimeArg(time.Now())
	policy := func(pid, name, groupID, userID string) {
		t.Helper()
		var g, u any
		if groupID != "" {
			g = groupID
		}
		if userID != "" {
			u = userID
		}
		if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO access_policies (id, name, description, enabled, group_id, user_id,
			target_selector, protocols, time_windows, idle_timeout_minutes, allow_clipboard, allow_file_transfer, require_mfa, require_approval,
			created_at, updated_at, rules) VALUES (?, ?, '', TRUE, ?, ?, '{"tags":{"env":"prod"}}', '["ssh"]', '[]', 15, FALSE, FALSE, TRUE, FALSE, ?, ?, '[]')`),
			pid, name, g, u, now, now); err != nil {
			t.Fatal(err)
		}
	}
	policy("p-web", "web", id, "")
	policy("p-db", "db", id, "")
	policy("p-ben", "ben-only", "", b.ID)

	if code, _ := do("DELETE", "/api/v1/groups/nope", nil); code != 404 || len(rv.deleted) != 0 {
		t.Fatalf("deleting an unknown group: %d, revoker asked about %v", code, rv.deleted)
	}
	if code, out := do("DELETE", "/api/v1/groups/"+id, nil); code != 204 {
		t.Fatalf("delete: %d %v", code, out)
	}
	if !slices.Equal(rv.deleted, []string{id}) || rv.boundThen[0] != 2 {
		t.Fatalf("revoker asked about %v (policies bound then: %v), want %s while its 2 policies existed", rv.deleted, rv.boundThen, id)
	}
	d := details("group.delete", id)
	removed, _ := d["policies_removed"].([]any)
	if d["live_sessions_ended"] != float64(3) || !slices.Equal(removed, []any{"p-db", "p-web"}) {
		t.Fatalf("group.delete details %v, want live_sessions_ended 3 and policies_removed [p-db p-web]", d)
	}
	var left int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_policies`).Scan(&left); err != nil || left != 1 {
		t.Fatalf("policies left after the delete: %d %v, want only ben-only", left, err)
	}
	if len(rv.unexpected) != 0 {
		t.Fatalf("unexpected revoker calls: %v", rv.unexpected)
	}
}

// TestDeleteReportsCascadedPolicies: deleting a group reports the policies
// bound to it, in name order, because the schema deletes them with it; a
// group with none reports an empty list, and an unknown group is not found.
func TestDeleteReportsCascadedPolicies(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	r := NewRepo(db)
	g, empty := &Group{Name: "ops"}, &Group{Name: "dev"}
	for _, x := range []*Group{g, empty} {
		if err := r.Create(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	now := store.TimeArg(time.Now())
	for _, p := range [][2]string{{"p2", "zeta"}, {"p1", "alpha"}} {
		if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO access_policies (id, name, description, enabled, group_id,
			target_selector, protocols, time_windows, idle_timeout_minutes, allow_clipboard, allow_file_transfer, require_mfa, require_approval,
			created_at, updated_at, rules) VALUES (?, ?, '', TRUE, ?, '{"tags":{"env":"prod"}}', '["ssh"]', '[]', 15, FALSE, FALSE, TRUE, FALSE, ?, ?, '[]')`),
			p[0], p[1], g.ID, now, now); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := r.Delete(ctx, g.ID)
	if err != nil || !slices.Equal(removed, []string{"p1", "p2"}) {
		t.Fatalf("delete ops: %v %v, want [p1 p2]", removed, err)
	}
	removed, err = r.Delete(ctx, empty.ID)
	if err != nil || removed == nil || len(removed) != 0 {
		t.Fatalf("delete dev: %#v %v, want an empty list", removed, err)
	}
	if _, err := r.Delete(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete unknown: %v, want not found", err)
	}
}
