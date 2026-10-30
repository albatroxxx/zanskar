// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/user"
)

// aHash stands in for a stored password: Resolve only asks whether there is
// one, and a real Argon2id hash costs a quarter of a second per account.
const aHash = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// groupCalls stands in for the group repository: it keeps memberships and
// records what Resolve asks of it.
type groupCalls struct {
	added, removed []string
	member         map[string]bool // groupID + "/" + userID
}

func (g *groupCalls) AddMember(_ context.Context, groupID, userID string) error {
	g.added = append(g.added, groupID+"/"+userID)
	if g.member == nil {
		g.member = map[string]bool{}
	}
	g.member[groupID+"/"+userID] = true
	return nil
}

func (g *groupCalls) RemoveMember(_ context.Context, groupID, userID string) error {
	g.removed = append(g.removed, groupID+"/"+userID)
	delete(g.member, groupID+"/"+userID)
	return nil
}

func (g *groupCalls) GroupIDsForUser(_ context.Context, userID string) ([]string, error) {
	var out []string
	for k := range g.member {
		if gid, uid, _ := strings.Cut(k, "/"); uid == userID {
			out = append(out, gid)
		}
	}
	return out, nil
}

type provisionEnv struct {
	repo   *Repo
	users  *user.Repo
	groups *groupCalls
	pv     *Provisioner
}

func newProvisionEnv(t *testing.T) *provisionEnv {
	t.Helper()
	ctx := context.Background()
	db := storetest.Open(t)
	kek, err := crypto.NewLocalKEK(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ring, err := keyring.Open(ctx, db, kek)
	if err != nil {
		t.Fatal(err)
	}
	e := &provisionEnv{repo: NewRepo(db, ring), users: user.NewRepo(db), groups: &groupCalls{}}
	e.pv = &Provisioner{Users: e.users, Groups: e.groups}
	return e
}

// provider stores an OIDC provider and returns it opened, as a sign-in sees
// it. The row is real: users.idp_id references it.
func (e *provisionEnv) provider(t *testing.T, name string, autoProvision bool) *Opened {
	t.Helper()
	ctx := context.Background()
	c := okOIDC()
	c.AutoProvision = autoProvision
	p := &Provider{Name: name, Type: TypeOIDC, Enabled: true}
	if err := e.repo.Create(ctx, p, c); err != nil {
		t.Fatal(err)
	}
	op, err := e.repo.Open(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

// local creates an account the way the admin API does; hash "" makes it
// password-less ("Signs in through an identity provider" in the console).
func (e *provisionEnv) local(t *testing.T, username, hash string, roles ...user.Role) *user.User {
	t.Helper()
	u := &user.User{Username: username, DisplayName: username, Roles: roles, PasswordHash: hash}
	if err := e.users.Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

func (e *provisionEnv) get(t *testing.T, id string) *user.User {
	t.Helper()
	u, err := e.users.GetByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (e *provisionEnv) count(t *testing.T) int {
	t.Helper()
	all, _, err := e.users.List(context.Background(), "", 500)
	if err != nil {
		t.Fatal(err)
	}
	return len(all)
}

func onlyRole(u *user.User, r user.Role) bool { return len(u.Roles) == 1 && u.Roles[0] == r }

// TestResolveAdoptsPreCreatedAccount reproduces H8. An administrator creates
// an account with no password for someone who signs in through an identity
// provider; with auto-provisioning off, that is the only way in. Resolve used
// to match on the external id alone, which only just-in-time provisioning
// ever set, so the sign-in was refused as not provisioned, every time. Now
// the first sign-in adopts the account: it is linked to the provider and the
// person's external id, keeps the roles the administrator chose, gets its
// mapped groups, and every later sign-in matches on the external id.
func TestResolveAdoptsPreCreatedAccount(t *testing.T) {
	e := newProvisionEnv(t)
	ctx := context.Background()
	p := e.provider(t, "corp", false)
	p.Config.GroupMapping = GroupMapping{"ops-team": "g-ops"}
	alice := e.local(t, "alice", "", user.RoleAdmin)
	id := Identity{ExternalID: "sub-1", Username: "Alice", DisplayName: "Alice Example", Email: "alice@corp.example", Groups: []string{"OPS-team"}}

	r, err := e.pv.Resolve(ctx, p, id)
	u, linked := r.User, r.Linked
	if err != nil {
		t.Fatalf("first sign-in of a pre-created password-less account: %v", err)
	}
	if u.ID != alice.ID || u.IdPID != p.ID || u.ExternalID != "sub-1" || !linked {
		t.Fatalf("got %s linked to %q/%q (linked=%v), want account %s linked to %q/sub-1", u.ID, u.IdPID, u.ExternalID, linked, alice.ID, p.ID)
	}
	if stored := e.get(t, alice.ID); stored.IdPID != p.ID || stored.ExternalID != "sub-1" {
		t.Fatalf("stored link %q/%q", stored.IdPID, stored.ExternalID)
	}
	if !onlyRole(u, user.RoleAdmin) {
		t.Fatalf("roles %v: adoption must keep the roles the administrator chose", u.Roles)
	}
	if u.DisplayName != "Alice Example" || u.Email != "alice@corp.example" {
		t.Fatalf("profile %q %q: the provider's name and email apply as at any sign-in", u.DisplayName, u.Email)
	}
	if strings.Join(e.groups.added, ",") != "g-ops/"+alice.ID {
		t.Fatalf("mapped groups: added %v", e.groups.added)
	}

	// The next sign-in matches on the external id, not the username: a
	// rename in the directory keeps the account.
	id.Username = "alice.renamed"
	r, err = e.pv.Resolve(ctx, p, id)
	again, linked := r.User, r.Linked
	if err != nil || again.ID != alice.ID || linked {
		t.Fatalf("second sign-in: %v linked=%v %v, want account %s matched, not linked again", again, linked, err, alice.ID)
	}
	if n := e.count(t); n != 1 {
		t.Fatalf("%d accounts, want 1", n)
	}
}

// TestResolveAdoptsRatherThanDuplicates: with auto-provisioning on, the first
// sign-in used to try to create the person and collide with the account
// already there ("username already exists locally"). It adopts that account
// now, with its own roles rather than the provider's default ones.
func TestResolveAdoptsRatherThanDuplicates(t *testing.T) {
	e := newProvisionEnv(t)
	ctx := context.Background()
	p := e.provider(t, "corp", true)
	alice := e.local(t, "alice", "", user.RoleAuditor)

	r, err := e.pv.Resolve(ctx, p, Identity{ExternalID: "sub-1", Username: "alice"})
	u, linked := r.User, r.Linked
	if err != nil {
		t.Fatalf("first sign-in with auto-provisioning on: %v", err)
	}
	if u.ID != alice.ID || u.IdPID != p.ID || u.ExternalID != "sub-1" || !onlyRole(u, user.RoleAuditor) || !linked {
		t.Fatalf("got %+v linked=%v, want account %s adopted with its auditor role", u, linked, alice.ID)
	}
	if n := e.count(t); n != 1 {
		t.Fatalf("%d accounts, want 1: the sign-in must not create a second one", n)
	}
}

// TestResolveRefusesAccountWithPassword: a provider never takes over a local
// account that has a password (the local admin kept for when the directory is
// down is one), whatever auto-provisioning says. The refusal says why and
// what to do, and nothing is linked.
func TestResolveRefusesAccountWithPassword(t *testing.T) {
	for _, auto := range []bool{false, true} {
		e := newProvisionEnv(t)
		ctx := context.Background()
		p := e.provider(t, "corp", auto)
		admin := e.local(t, "admin", aHash, user.RoleAdmin)

		_, err := e.pv.Resolve(ctx, p, Identity{ExternalID: "sub-1", Username: "admin"})
		if !errors.Is(err, ErrAccountConflict) || !strings.Contains(err.Error(), `"admin" has a password; remove it or rename one of them`) {
			t.Fatalf("auto_provision=%v: got %v, want a refusal that names the password", auto, err)
		}
		if got := e.get(t, admin.ID); got.IdPID != "" || got.ExternalID != "" {
			t.Fatalf("auto_provision=%v: the password account was linked to %q/%q", auto, got.IdPID, got.ExternalID)
		}
		if n := e.count(t); n != 1 {
			t.Fatalf("auto_provision=%v: %d accounts, want 1", auto, n)
		}
	}
}

// TestResolveRefusesAccountLinkedElsewhere: an account already linked to one
// identity is never moved to another by a sign-in, whether the other is a
// second provider or a different subject at the same one (a directory account
// deleted and re-created gets a new objectGUID).
func TestResolveRefusesAccountLinkedElsewhere(t *testing.T) {
	for _, auto := range []bool{false, true} {
		e := newProvisionEnv(t)
		ctx := context.Background()
		a := e.provider(t, "corp-a", auto)
		b := e.provider(t, "corp-b", true)
		r, err := e.pv.Resolve(ctx, b, Identity{ExternalID: "b-sub", Username: "alice"})
		alice := r.User
		if err != nil {
			t.Fatal(err)
		}

		r, err = e.pv.Resolve(ctx, a, Identity{ExternalID: "a-sub", Username: "alice"})
		if !errors.Is(err, ErrAccountConflict) || !strings.Contains(err.Error(), `"alice" is linked to another identity provider`) {
			t.Fatalf("auto_provision=%v: provider A on B's account: got %v, want a refusal", auto, err)
		}
		r, err = e.pv.Resolve(ctx, b, Identity{ExternalID: "b-sub-2", Username: "alice"})
		if !errors.Is(err, ErrAccountConflict) || !strings.Contains(err.Error(), `"alice" is linked to a different identity at this provider`) {
			t.Fatalf("auto_provision=%v: another subject at B: got %v, want a refusal", auto, err)
		}
		if got := e.get(t, alice.ID); got.IdPID != b.ID || got.ExternalID != "b-sub" {
			t.Fatalf("auto_provision=%v: link moved to %q/%q", auto, got.IdPID, got.ExternalID)
		}
		if n := e.count(t); n != 1 {
			t.Fatalf("auto_provision=%v: %d accounts, want 1", auto, n)
		}
	}
}

// TestResolveDoesNotLinkDisabledAccount: a disabled account is refused, as at
// any sign-in, and is not linked on the way.
func TestResolveDoesNotLinkDisabledAccount(t *testing.T) {
	e := newProvisionEnv(t)
	ctx := context.Background()
	p := e.provider(t, "corp", false)
	alice := e.local(t, "alice", "", user.RoleUser)
	if err := e.users.Update(ctx, alice.ID, "alice", "", user.StatusDisabled); err != nil {
		t.Fatal(err)
	}

	_, err := e.pv.Resolve(ctx, p, Identity{ExternalID: "sub-1", Username: "alice"})
	if err == nil || !strings.Contains(err.Error(), "disabled or locked") {
		t.Fatalf("got %v, want the disabled-account refusal", err)
	}
	if got := e.get(t, alice.ID); got.IdPID != "" || got.ExternalID != "" {
		t.Fatalf("a disabled account was linked to %q/%q", got.IdPID, got.ExternalID)
	}
}

// TestResolveCreatesWhenDirectoryUsernameDiffers: adoption goes by the
// username the provider asserts and nothing else. A person the directory
// calls alice.smith is not the pre-created alice: with auto-provisioning on
// they get an account of their own with the provider's default roles, and
// alice is left as she was; with it off they are refused as before.
func TestResolveCreatesWhenDirectoryUsernameDiffers(t *testing.T) {
	e := newProvisionEnv(t)
	ctx := context.Background()
	p := e.provider(t, "corp", true)
	alice := e.local(t, "alice", "", user.RoleAdmin)

	r, err := e.pv.Resolve(ctx, p, Identity{ExternalID: "sub-1", Username: "alice.smith", Email: "alice@corp.example"})
	u, linked := r.User, r.Linked
	if err != nil {
		t.Fatal(err)
	}
	if u.ID == alice.ID || u.Username != "alice.smith" || u.IdPID != p.ID || u.ExternalID != "sub-1" || !onlyRole(u, user.RoleUser) || linked {
		t.Fatalf("got %+v linked=%v, want a new alice.smith with the default role", u, linked)
	}
	if got := e.get(t, alice.ID); got.IdPID != "" || got.ExternalID != "" {
		t.Fatalf("alice was linked to %q/%q", got.IdPID, got.ExternalID)
	}

	q := e.provider(t, "closed", false)
	if _, err := e.pv.Resolve(ctx, q, Identity{ExternalID: "sub-9", Username: "alice.jones"}); !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("no matching account and auto-provisioning off: got %v, want ErrNotProvisioned", err)
	}
	if n := e.count(t); n != 2 {
		t.Fatalf("%d accounts, want 2", n)
	}
}

// TestResolveGroupDNMappingIsExact: an LDAP mapping key written as a DN
// matches that group only, not a same-named group someone created in
// another OU; a bare-name key still matches by name, as before.
func TestResolveGroupDNMappingIsExact(t *testing.T) {
	e := newProvisionEnv(t)
	ctx := context.Background()
	p := e.provider(t, "dir", true)
	p.Config.GroupMapping = GroupMapping{"cn=zanskar-admins,ou=groups,dc=corp,dc=example": "g-admins"}

	planted := Identity{ExternalID: "sub-1", Username: "mallory", Groups: []string{"zanskar-admins"},
		GroupDNs: []string{"cn=zanskar-admins,ou=contractors,dc=corp,dc=example"}}
	if r, err := e.pv.Resolve(ctx, p, planted); err != nil || len(r.GroupsAdded) != 0 {
		t.Fatalf("a same-named group in another OU joined the mapped group: %+v %v", r.GroupsAdded, err)
	}
	mapped := Identity{ExternalID: "sub-2", Username: "alice", Groups: []string{"zanskar-admins"},
		GroupDNs: []string{"CN=Zanskar-Admins, OU=Groups, DC=corp, DC=example"}}
	if r, err := e.pv.Resolve(ctx, p, mapped); err != nil || strings.Join(r.GroupsAdded, ",") != "g-admins" {
		t.Fatalf("the mapped DN, written differently, must match: %+v %v", r.GroupsAdded, err)
	}
	p.Config.GroupMapping = GroupMapping{"zanskar-admins": "g-admins"}
	if r, err := e.pv.Resolve(ctx, p, Identity{ExternalID: "sub-3", Username: "bob", Groups: []string{"Zanskar-Admins"}}); err != nil || strings.Join(r.GroupsAdded, ",") != "g-admins" {
		t.Fatalf("a bare-name key matches by name: %+v %v", r.GroupsAdded, err)
	}
}

// sessionEnder records what a sign-in asked the gateway to end.
type sessionEnder struct {
	gateway.Revoker // only Recheck is used here
	calls           []string
}

func (s *sessionEnder) Recheck(_ context.Context, userIDs []string) int {
	s.calls = append(s.calls, strings.Join(userIDs, ","))
	return 3
}

// TestResolveReportsWhatItDid: a provisioned account and the group changes
// a sign-in makes come back to the caller, which audits them; a removal
// from a mapped group re-checks the person's live sessions (ADR 0036).
func TestResolveReportsWhatItDid(t *testing.T) {
	e := newProvisionEnv(t)
	ctx := context.Background()
	ender := &sessionEnder{}
	e.pv.Revoker = ender
	p := e.provider(t, "corp", true)
	p.Config.DefaultRoles = []user.Role{user.RoleAdmin}
	p.Config.GroupMapping = GroupMapping{"ops-team": "g-ops", "dev-team": "g-dev"}

	r, err := e.pv.Resolve(ctx, p, Identity{ExternalID: "sub-1", Username: "carol", Groups: []string{"ops-team", "dev-team"}})
	if err != nil || !r.Created || r.Linked {
		t.Fatalf("first sign-in: %+v %v", r, err)
	}
	evs := r.Events("192.0.2.7", p, Identity{ExternalID: "sub-1"})
	if len(evs) != 2 || evs[0].Action != "user.create" || evs[1].Action != "user.groups.sync" {
		t.Fatalf("events: %v", actions(evs))
	}
	var created map[string]any
	_ = json.Unmarshal(evs[0].Details, &created)
	if created["via"] != "identity_provider" || fmt.Sprint(created["roles_granted"]) != "[admin]" || evs[0].ActorIP != "192.0.2.7" {
		t.Fatalf("the provisioned admin is not on the record: %v", created)
	}

	// The directory drops carol from ops-team: she leaves g-ops, and what
	// g-ops granted ends.
	r, err = e.pv.Resolve(ctx, p, Identity{ExternalID: "sub-1", Username: "carol", Groups: []string{"dev-team"}})
	if err != nil || r.Created || len(r.GroupsAdded) != 0 || strings.Join(r.GroupsRemoved, ",") != "g-ops" || r.LiveSessionsEnded != 3 {
		t.Fatalf("second sign-in: %+v %v", r, err)
	}
	if strings.Join(ender.calls, ";") != r.User.ID {
		t.Fatalf("sessions ended: %v", ender.calls)
	}
	evs = r.Events("192.0.2.7", p, Identity{ExternalID: "sub-1"})
	var sync map[string]any
	if len(evs) != 1 || json.Unmarshal(evs[0].Details, &sync) != nil || sync["live_sessions_ended"] != float64(3) {
		t.Fatalf("group sync event: %v %v", actions(evs), sync)
	}
	// A sign-in that changes nothing records nothing extra.
	if r, _ = e.pv.Resolve(ctx, p, Identity{ExternalID: "sub-1", Username: "carol", Groups: []string{"dev-team"}}); len(r.Events("", p, Identity{})) != 0 {
		t.Fatal("an unchanged sign-in recorded events")
	}
}

func actions(evs []audit.Event) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Action)
	}
	return out
}
