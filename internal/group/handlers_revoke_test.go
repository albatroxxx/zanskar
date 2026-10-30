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

// liveRevoker stands in for the gateway. It records whom it was asked to
// re-check and, at each call, how many policies still named the group, so a
// test can tell a re-check made after the change from one made before it.
type liveRevoker struct {
	db         *store.DB
	group      string
	ended      int
	rechecked  [][]string
	namedThen  []int // policies naming the group at each Recheck
	unexpected []string
}

func (f *liveRevoker) Recheck(ctx context.Context, userIDs []string) int {
	n := -1
	_ = f.db.QueryRowContext(ctx, f.db.Rebind(`SELECT COUNT(*) FROM access_policy_subjects WHERE group_id = ?`), f.group).Scan(&n)
	f.rechecked = append(f.rechecked, slices.Clone(userIDs))
	f.namedThen = append(f.namedThen, n)
	return f.ended
}

func (f *liveRevoker) UserRevoked(string) int {
	f.unexpected = append(f.unexpected, "UserRevoked")
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

// TestGroupChangesEndLiveSessions (ADR 0036): taking members out of a group
// re-checks their live sessions, and deleting the group re-checks its
// members' once it is gone, so the check sees the access they hold without
// it. The group leaves its policies; the policies stay. Each event says how
// many sessions ended; the deletion names the policies the group left.
func TestGroupChangesEndLiveSessions(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{3}, 32), false)
	auditLog := audit.NewLog(db)
	groups := NewRepo(db)
	rv := &liveRevoker{db: db, ended: 3}
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
	rv.group = id
	if code, out := do("PUT", "/api/v1/groups/"+id+"/members", map[string]any{"user_ids": []string{a.ID, b.ID}}); code != 200 {
		t.Fatalf("add members: %d %v", code, out)
	}
	if len(rv.rechecked) != 0 {
		t.Fatalf("adding members re-checked %v", rv.rechecked)
	}
	if _, ok := details("group.members.update", id)["live_sessions_ended"]; ok {
		t.Fatal("adding members claims live sessions ended")
	}

	if code, out := do("PUT", "/api/v1/groups/"+id+"/members", map[string]any{"user_ids": []string{b.ID}}); code != 200 {
		t.Fatalf("remove a member: %d %v", code, out)
	}
	if len(rv.rechecked) != 1 || !slices.Equal(rv.rechecked[0], []string{a.ID}) {
		t.Fatalf("revoker re-checked %v, want [[%s]]", rv.rechecked, a.ID)
	}
	if d := details("group.members.update", id); d["live_sessions_ended"] != float64(3) {
		t.Fatalf("group.members.update details %v, want live_sessions_ended 3", d)
	}

	// Two policies name the group, one names a user: deleting the group
	// takes it out of the first two, and all three stay.
	policy := func(pid, name, groupID, userID string) {
		t.Helper()
		insertPolicy(t, db, pid, name, groupID, userID)
	}
	policy("p-web", "web", id, "")
	policy("p-db", "db", id, "")
	policy("p-ben", "ben-only", "", b.ID)

	if code, _ := do("DELETE", "/api/v1/groups/nope", nil); code != 404 || len(rv.rechecked) != 1 {
		t.Fatalf("deleting an unknown group: %d, revoker re-checked %v", code, rv.rechecked)
	}
	if code, out := do("DELETE", "/api/v1/groups/"+id, nil); code != 204 {
		t.Fatalf("delete: %d %v", code, out)
	}
	if len(rv.rechecked) != 2 || !slices.Equal(rv.rechecked[1], []string{b.ID}) || rv.namedThen[1] != 0 {
		t.Fatalf("revoker re-checked %v (policies naming the group then: %v), want [%s] once the group was gone", rv.rechecked, rv.namedThen, b.ID)
	}
	d := details("group.delete", id)
	detached, _ := d["policies_detached"].([]any)
	if d["live_sessions_ended"] != float64(3) || !slices.Equal(detached, []any{"db", "web"}) {
		t.Fatalf("group.delete details %v, want live_sessions_ended 3 and policies_detached [db web]", d)
	}
	var left int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_policies`).Scan(&left); err != nil || left != 3 {
		t.Fatalf("policies left after the delete: %d %v, want all three", left, err)
	}
	if len(rv.unexpected) != 0 {
		t.Fatalf("unexpected revoker calls: %v", rv.unexpected)
	}
}

// TestDeleteReportsDetachedPolicies (ADR 0036): deleting a group reports, in
// name order, the policies that named it, which it leaves and which stay; a
// group named by none reports an empty list, and an unknown group is not
// found.
func TestDeleteReportsDetachedPolicies(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	r := NewRepo(db)
	g, empty := &Group{Name: "ops"}, &Group{Name: "dev"}
	for _, x := range []*Group{g, empty} {
		if err := r.Create(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range [][2]string{{"p2", "zeta"}, {"p1", "alpha"}} {
		insertPolicy(t, db, p[0], p[1], g.ID, "")
	}
	removed, err := r.Delete(ctx, g.ID)
	if err != nil || !slices.Equal(removed, []string{"alpha", "zeta"}) {
		t.Fatalf("delete ops: %v %v, want [alpha zeta]", removed, err)
	}
	removed, err = r.Delete(ctx, empty.ID)
	if err != nil || removed == nil || len(removed) != 0 {
		t.Fatalf("delete dev: %#v %v, want an empty list", removed, err)
	}
	if _, err := r.Delete(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete unknown: %v, want not found", err)
	}
}

// insertPolicy stores a policy row naming one group or user, as the policy
// package would (ADR 0036): the row, and its subject.
func insertPolicy(t *testing.T, db *store.DB, id, name, groupID, userID string) {
	t.Helper()
	ctx := context.Background()
	now := store.TimeArg(time.Now())
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO access_policies (id, name, description, enabled, grants, created_at, updated_at)
		VALUES (?, ?, '', TRUE, '[]', ?, ?)`), id, name, now, now); err != nil {
		t.Fatal(err)
	}
	var g, u any
	if groupID != "" {
		g = groupID
	}
	if userID != "" {
		u = userID
	}
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO access_policy_subjects (policy_id, group_id, user_id) VALUES (?, ?, ?)`), id, g, u); err != nil {
		t.Fatal(err)
	}
}
