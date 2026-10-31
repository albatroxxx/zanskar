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

// TestRemoveTargetOnEachBackend (ADR 0036, amended 2026-10-30): deleting a
// target rewrites, inside the deletion's transaction, the grants that name
// it on both engines' JSON columns: the target leaves a grant naming others;
// a grant naming only it goes, unless a tag rule keeps it; a policy left
// with no grant stays; a policy that never named it is not touched; an
// autoscaling grant is matched by the group's id, never by a target's. The
// preview says the same before anything is written.
func TestRemoveTargetOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		seedPeople(t, db)
		r := NewRepo(db)
		subj := []Subject{{Kind: SubjectGroup, ID: "g1"}}
		host := func(ids ...string) Grant {
			g := Grant{Kind: protocol.KindHost}
			for _, id := range ids {
				g.Targets = append(g.Targets, GrantTarget{ID: id, Protocols: []string{"ssh"}})
			}
			return g
		}
		withTag := host("t1")
		withTag.Tags = &TagMatch{Match: map[string][]string{"env": {"prod"}}, Protocols: []string{"ssh"}}
		ps := []*Policy{
			{Name: "a-shared", Enabled: true, Subjects: subj, Grants: []Grant{host("t1", "t2")}},
			{Name: "b-only", Enabled: true, Subjects: subj, Grants: []Grant{host("t1")}},
			{Name: "c-tagged", Enabled: true, Subjects: subj, Grants: []Grant{withTag, host("t1")}},
			{Name: "d-other", Enabled: true, Subjects: subj, Grants: []Grant{host("t2")}},
			{Name: "e-fleet", Enabled: true, Subjects: subj, Grants: []Grant{{Kind: protocol.KindAutoscaling, Targets: []GrantTarget{{ID: "t1", Protocols: []string{"ssh"}}}}}},
		}
		for _, p := range ps {
			if err := r.Create(ctx, p); err != nil {
				t.Fatal(err)
			}
		}
		preview, err := r.TargetUsage(ctx, "t1", "")
		if err != nil {
			t.Fatal(err)
		}
		// The stored time, not Create's: the database keeps less precision
		// than a Linux clock, so the two never compare equal there.
		stored, err := r.Get(ctx, ps[3].ID)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		done, err := r.RemoveTargetTx(ctx, tx, "t1", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		want := []Removal{
			{PolicyID: ps[0].ID, Name: "a-shared"},
			{PolicyID: ps[1].ID, Name: "b-only", GrantsRemoved: 1, NoGrantsLeft: true},
			{PolicyID: ps[2].ID, Name: "c-tagged", GrantsRemoved: 1},
		}
		if !slices.Equal(done, want) || !slices.Equal(preview, want) {
			t.Fatalf("removals:\n done    %+v\n preview %+v\n want    %+v", done, preview, want)
		}
		get := func(i int) *Policy {
			p, err := r.Get(ctx, ps[i].ID)
			if err != nil {
				t.Fatal(err)
			}
			return p
		}
		if g := get(0).Grants; len(g) != 1 || len(g[0].Targets) != 1 || g[0].Targets[0].ID != "t2" {
			t.Fatalf("a-shared: %+v", g)
		}
		if g := get(1).Grants; len(g) != 0 {
			t.Fatalf("b-only: %+v", g)
		}
		if g := get(2).Grants; len(g) != 1 || g[0].Tags == nil || len(g[0].Targets) != 0 {
			t.Fatalf("c-tagged: %+v", g)
		}
		if p := get(3); !p.UpdatedAt.Equal(stored.UpdatedAt) || len(p.Grants[0].Targets) != 1 {
			t.Fatalf("d-other was rewritten: %+v", p)
		}
		if g := get(4).Grants; len(g) != 1 || g[0].Targets[0].ID != "t1" {
			t.Fatalf("an autoscaling grant lost a group that shares the deleted target's id: %+v", g)
		}
	})
}

// TestCountStandingNoMFAOnEachBackend (2026-10-31, the dashboard's security
// posture): standing grants without an authenticator, counted in enabled
// policies only; approval grants and grants that ask for MFA are not.
func TestCountStandingNoMFAOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		seedPeople(t, db)
		r := NewRepo(db)
		subj := []Subject{{Kind: SubjectGroup, ID: "g1"}}
		grant := func(access string, mfa bool) Grant {
			return Grant{Kind: protocol.KindHost, Targets: []GrantTarget{{ID: "t1", Protocols: []string{"ssh"}}}, Access: access, RequireMFA: mfa}
		}
		ps := []*Policy{
			{Name: "a-open", Enabled: true, Subjects: subj, Grants: []Grant{grant(AccessStanding, false), grant(AccessStanding, false), grant(AccessStanding, true)}},
			{Name: "b-approval", Enabled: true, Subjects: subj, Grants: []Grant{grant(AccessApproval, false)}},
			{Name: "c-mfa", Enabled: true, Subjects: subj, Grants: []Grant{grant(AccessStanding, true)}},
			{Name: "d-off", Enabled: false, Subjects: subj, Grants: []Grant{grant(AccessStanding, false)}},
			{Name: "e-one", Enabled: true, Subjects: subj, Grants: []Grant{grant(AccessStanding, false)}},
		}
		for _, p := range ps {
			if err := r.Create(ctx, p); err != nil {
				t.Fatal(err)
			}
		}
		e, err := r.CountStandingNoMFA(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if e != (Exposure{Grants: 3, Policies: 2}) {
			t.Fatalf("exposure %+v, want 3 grants in 2 policies", e)
		}
	})
}
