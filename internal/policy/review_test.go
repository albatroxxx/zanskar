// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/user"
)

// testDirectory names people and groups from the test database.
type testDirectory struct {
	users *user.Repo
	db    *store.DB
}

func (d testDirectory) UserName(ctx context.Context, id string) (string, error) {
	u, err := d.users.GetByID(ctx, id)
	if err != nil {
		return "", nil
	}
	return u.Username, nil
}

func (d testDirectory) Group(ctx context.Context, id string) (string, []Person, error) {
	var name string
	if err := d.db.QueryRowContext(ctx, d.db.Rebind(`SELECT name FROM groups WHERE id = ?`), id).Scan(&name); err != nil {
		return "", nil, nil
	}
	rows, err := d.db.QueryContext(ctx, d.db.Rebind(`SELECT u.id, u.username FROM group_members m JOIN users u ON u.id = m.user_id WHERE m.group_id = ? ORDER BY u.username`), id)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Person
	for rows.Next() {
		var p Person
		if err := rows.Scan(&p.UserID, &p.Username); err != nil {
			return "", nil, err
		}
		out = append(out, p)
	}
	return name, out, rows.Err()
}

// startedSession writes a session of userID under policyID, started at at.
func startedSession(t *testing.T, db *store.DB, id, userID, policyID string, at time.Time) {
	t.Helper()
	ctx := context.Background()
	now := store.TimeArg(at)
	_, _ = db.ExecContext(ctx, db.Rebind(`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('web-1', 'web-1', '10.0.0.5', 'linux', ?, ?)`), now, now)
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO access_sessions (id, user_id, policy_id, target_id, protocol, client_ip, user_agent, started_at) VALUES (?, ?, ?, 'web-1', 'ssh', '10.0.0.1', '', ?)`),
		id, userID, policyID, now); err != nil {
		t.Fatal(err)
	}
}

// 2026-11-03, idea 4 (ADR 0040): an access review lists the people a policy
// covers, through groups too, with when each last used it; the decisions
// remove who no longer needs it, end what that took away, stamp the policy
// reviewed and record who was kept and removed, and why.
func TestAccessReview(t *testing.T) {
	e := newHandlerEnv(t)
	body := e.body()
	body["subjects"] = []map[string]string{{"kind": "group", "id": e.group}, {"kind": "user", "id": e.ben.ID}}
	code, out := e.do("POST", "/api/v1/access-policies", body)
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	id := out["id"].(string)
	used := time.Now().Add(-10 * 24 * time.Hour).UTC().Truncate(time.Second)
	startedSession(t, e.db, "s1", e.ann.ID, id, used)

	code, out = e.do("GET", "/api/v1/access-policies/"+id+"/review", nil)
	if code != 200 || out["due"] != true {
		t.Fatalf("review: %d %v", code, out)
	}
	subjects := out["subjects"].([]any)
	if len(subjects) != 2 {
		t.Fatalf("subjects: %v", subjects)
	}
	ops, ben := subjects[0].(map[string]any), subjects[1].(map[string]any)
	people := ops["people"].([]any)
	if ops["name"] != "ops" || len(people) != 1 || people[0].(map[string]any)["username"] != "ann" || people[0].(map[string]any)["last_used_at"] == nil {
		t.Fatalf("the group's people and their last use: %v", ops)
	}
	if ben["name"] != "ben" || ben["last_used_at"] != nil {
		t.Fatalf("a person who never used it: %v", ben)
	}

	// Removing someone who is not a subject is refused, and changes nothing.
	if code, _ := e.do("POST", "/api/v1/access-policies/"+id+"/review", map[string]any{"remove": []map[string]string{{"kind": "user", "id": e.ann.ID}}}); code != 422 {
		t.Fatalf("an unknown subject: %d", code)
	}

	code, out = e.do("POST", "/api/v1/access-policies/"+id+"/review", map[string]any{
		"remove": []map[string]string{{"kind": "user", "id": e.ben.ID}}, "note": "ben moved teams",
	})
	if code != 200 || out["due"] != false || out["reviewer_name"] != "admin" || len(out["subjects"].([]any)) != 1 {
		t.Fatalf("complete: %d %v", code, out)
	}
	d := e.lastEvent(t, "policy.review")
	if d["note"] != "ben moved teams" || len(d["removed"].([]any)) != 1 || len(d["kept"].([]any)) != 1 {
		t.Fatalf("policy.review: %v", d)
	}
	// What ben's removal took away is re-checked.
	if last := e.rv.rechecked[len(e.rv.rechecked)-1]; !slices.Contains(last, e.ben.ID) {
		t.Fatalf("ben's sessions were not re-checked: %v", e.rv.rechecked)
	}

	// Keeping everyone still stamps the review.
	code, out = e.do("POST", "/api/v1/access-policies/"+id+"/review", map[string]any{})
	if code != 200 || out["policy"].(map[string]any)["reviewed_at"] == nil {
		t.Fatalf("a review that keeps everyone: %d %v", code, out)
	}
}

// LastUse is a MAX over timestamps grouped by person: both engines.
func TestLastUse(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		users := user.NewRepo(db)
		u := &user.User{Username: "ann", DisplayName: "ann", Roles: []user.Role{user.RoleUser}}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		r := NewRepo(db)
		p := &Policy{Name: "p", Enabled: true, Subjects: []Subject{{Kind: SubjectUser, ID: u.ID}},
			Grants: []Grant{{Kind: "host", Targets: []GrantTarget{{ID: "web-1", Protocols: []string{"ssh"}}}, Access: AccessStanding, SignIn: SignInTarget, IdleTimeoutMinutes: 15}}}
		if err := r.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
		older := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
		newer := time.Date(2026, 10, 20, 9, 0, 0, 123000, time.UTC)
		startedSession(t, db, "s1", u.ID, p.ID, older)
		startedSession(t, db, "s2", u.ID, p.ID, newer)
		got, err := r.LastUse(ctx, p.ID)
		if err != nil || !got[u.ID].Equal(newer) {
			t.Fatalf("last use %v %v, want %v", got, err, newer)
		}
		if err := r.Reviewed(ctx, p.ID, u.ID, newer); err != nil {
			t.Fatal(err)
		}
		again, _ := r.Get(ctx, p.ID)
		if again.ReviewedAt == nil || !again.ReviewedAt.Equal(newer) || again.ReviewedBy != u.ID {
			t.Fatalf("reviewed: %+v", again)
		}
	})
}
