// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// seedPeople stores users u1..u3, group g1 holding u1 and u2, and group g2
// holding u3, straight into the tables the repository joins on.
func seedPeople(t *testing.T, db *store.DB) {
	t.Helper()
	ctx := context.Background()
	now := store.TimeArg(time.Now())
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1', 'ann', 'Ann', ?, ?)`, []any{now, now}},
		{`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u2', 'ben', 'Ben', ?, ?)`, []any{now, now}},
		{`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u3', 'cat', 'Cat', ?, ?)`, []any{now, now}},
		{`INSERT INTO groups (id, name, created_at, updated_at) VALUES ('g1', 'ops', ?, ?)`, []any{now, now}},
		{`INSERT INTO groups (id, name, created_at, updated_at) VALUES ('g2', 'dba', ?, ?)`, []any{now, now}},
		{`INSERT INTO group_members (group_id, user_id, added_at) VALUES ('g1', 'u1', ?)`, []any{now}},
		{`INSERT INTO group_members (group_id, user_id, added_at) VALUES ('g1', 'u2', ?)`, []any{now}},
		{`INSERT INTO group_members (group_id, user_id, added_at) VALUES ('g2', 'u3', ?)`, []any{now}},
	} {
		if _, err := db.ExecContext(ctx, db.Rebind(q.sql), q.args...); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRepoOnEachBackend (ADR 0036): subjects live in their own table and
// come back with every read; grants survive the JSON column on both
// engines; ForUser reaches a person directly and through a group; deleting a
// group or a user takes it out of its policies, which stay.
func TestRepoOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		seedPeople(t, db)
		r := NewRepo(db)
		week := []TimeWindow{{Days: []string{"mon", "tue"}, From: "09:00", To: "18:00", TZ: "Asia/Kolkata"}}
		full := &Policy{Name: "platform", Enabled: true,
			Subjects: []Subject{{Kind: SubjectUser, ID: "u3"}, {Kind: SubjectGroup, ID: "g1"}},
			Grants: []Grant{
				{Kind: protocol.KindHost, Targets: []GrantTarget{{ID: "t1", Protocols: []string{"ssh", "rdp"}}},
					Tags:   &TagMatch{Match: map[string][]string{"env": {"prod", "staging"}}, Protocols: []string{"ssh"}},
					Access: AccessApproval, SignIn: SignInOwn, RequireMFA: true, AllowClipboard: true,
					IdleTimeoutMinutes: 20, MaxSessionMinutes: intp(90), TimeWindows: week, RetentionDays: intp(365)},
				{Kind: protocol.KindDatabase, Targets: []GrantTarget{{ID: "d1", Protocols: []string{"database"}}}},
			}}
		if err := r.Create(ctx, full); err != nil {
			t.Fatal(err)
		}
		if full.ID == "" || full.Grants[0].ID == "" || full.Grants[1].ID == "" || full.Grants[0].ID == full.Grants[1].ID {
			t.Fatalf("ids not given: %q %+v", full.ID, full.Grants)
		}
		got, err := r.Get(ctx, full.ID)
		if err != nil {
			t.Fatal(err)
		}
		// Groups first, then users.
		if want := []Subject{{Kind: SubjectGroup, ID: "g1"}, {Kind: SubjectUser, ID: "u3"}}; !slices.Equal(got.Subjects, want) {
			t.Fatalf("subjects %v, want %v", got.Subjects, want)
		}
		if !reflect.DeepEqual(got.Grants, full.Grants) {
			t.Fatalf("grants did not round-trip:\ngot  %+v\nwant %+v", got.Grants, full.Grants)
		}

		// A name is unique.
		if err := r.Create(ctx, &Policy{Name: "platform", Enabled: true, Subjects: []Subject{{Kind: SubjectGroup, ID: "g2"}}, Grants: full.Grants[1:]}); !errors.Is(err, ErrDuplicate) {
			t.Fatalf("a second platform: %v", err)
		}
		// A subject that does not exist is refused, and nothing is stored.
		if err := r.Create(ctx, &Policy{Name: "ghost", Enabled: true, Subjects: []Subject{{Kind: SubjectGroup, ID: "nope"}}, Grants: full.Grants[1:]}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("a missing group: %v", err)
		}
		if _, err := r.Get(ctx, "ghost"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("the refused policy left a row: %v", err)
		}

		other := &Policy{Name: "dba", Enabled: true, Subjects: []Subject{{Kind: SubjectGroup, ID: "g2"}}, Grants: full.Grants[1:]}
		off := &Policy{Name: "off", Enabled: false, Subjects: []Subject{{Kind: SubjectUser, ID: "u1"}}, Grants: full.Grants[1:]}
		for _, p := range []*Policy{other, off} {
			p.Grants = slices.Clone(p.Grants)
			p.Grants[0].ID = ""
			if err := r.Create(ctx, p); err != nil {
				t.Fatal(err)
			}
		}
		names := func(ps []*Policy) []string {
			var out []string
			for _, p := range ps {
				out = append(out, p.Name)
			}
			return out
		}
		for user, want := range map[string][]string{"u1": {"platform"}, "u2": {"platform"}, "u3": {"dba", "platform"}} {
			ps, err := r.ForUser(ctx, user)
			if err != nil || !slices.Equal(names(ps), want) {
				t.Fatalf("ForUser(%s) = %v %v, want %v (enabled only, by name)", user, names(ps), err, want)
			}
		}
		if ps, err := r.ForGroup(ctx, "g1"); err != nil || !slices.Equal(names(ps), []string{"platform"}) {
			t.Fatalf("ForGroup(g1) = %v %v", names(ps), err)
		}
		if users, err := r.UsersCovered(ctx, got.Subjects); err != nil || !slices.Equal(users, []string{"u1", "u2", "u3"}) {
			t.Fatalf("UsersCovered = %v %v", users, err)
		}

		// An edit replaces the subjects with the ones given.
		got.Subjects = []Subject{{Kind: SubjectUser, ID: "u2"}}
		if err := r.Update(ctx, got); err != nil {
			t.Fatal(err)
		}
		if ps, _ := r.ForUser(ctx, "u1"); len(ps) != 0 {
			t.Fatalf("u1 still reached after the group left the policy: %v", names(ps))
		}

		// Deleting the group named by dba leaves dba, with no subject.
		if _, err := db.ExecContext(ctx, db.Rebind(`DELETE FROM groups WHERE id = ?`), "g2"); err != nil {
			t.Fatal(err)
		}
		if p, err := r.Get(ctx, other.ID); err != nil || len(p.Subjects) != 0 {
			t.Fatalf("dba after its group went: %+v %v", p, err)
		}
		// So does deleting a user.
		if _, err := db.ExecContext(ctx, db.Rebind(`DELETE FROM users WHERE id = ?`), "u2"); err != nil {
			t.Fatal(err)
		}
		if p, err := r.Get(ctx, got.ID); err != nil || len(p.Subjects) != 0 {
			t.Fatalf("platform after its user went: %+v %v", p, err)
		}

		// The list carries subjects, and deleting a policy removes its rows.
		list, _, err := r.List(ctx, "", 50)
		if err != nil || !slices.Equal(names(list), []string{"dba", "off", "platform"}) || len(list[1].Subjects) != 1 {
			t.Fatalf("list: %v %v", names(list), err)
		}
		if err := r.Delete(ctx, off.ID); err != nil {
			t.Fatal(err)
		}
		var left int
		if err := db.QueryRowContext(ctx, db.Rebind(`SELECT COUNT(*) FROM access_policy_subjects WHERE policy_id = ?`), off.ID).Scan(&left); err != nil || left != 0 {
			t.Fatalf("subjects left behind: %d %v", left, err)
		}
		if err := r.Delete(ctx, off.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a second delete: %v", err)
		}
	})
}

// TestReferencingOnEachBackend: the deletion guard finds a policy that names
// a target or a group by id, not one that matches it by tag.
func TestReferencingOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		seedPeople(t, db)
		r := NewRepo(db)
		subj := []Subject{{Kind: SubjectGroup, ID: "g1"}}
		for _, p := range []*Policy{
			{Name: "names-t1", Enabled: true, Subjects: subj, Grants: []Grant{{Kind: protocol.KindHost, Targets: []GrantTarget{{ID: "t1", Protocols: []string{"ssh"}}}}}},
			{Name: "names-fleet", Enabled: true, Subjects: subj, Grants: []Grant{{Kind: protocol.KindAutoscaling, Targets: []GrantTarget{{ID: "a1", Protocols: []string{"ssh"}}}}}},
			{Name: "tags", Enabled: true, Subjects: subj, Grants: []Grant{{Kind: protocol.KindHost, Tags: &TagMatch{Match: map[string][]string{"env": {"prod"}}, Protocols: []string{"ssh"}}}}},
		} {
			if err := r.Create(ctx, p); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := r.Referencing(ctx, "t1", ""); err != nil || !slices.Equal(got, []string{"names-t1"}) {
			t.Fatalf("target t1: %v %v", got, err)
		}
		if got, err := r.Referencing(ctx, "", "a1"); err != nil || !slices.Equal(got, []string{"names-fleet"}) {
			t.Fatalf("group a1: %v %v", got, err)
		}
	})
}
