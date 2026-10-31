// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/user"
)

// fakeDirectory lists whoever is in people, or fails with err. block, when
// set, holds a listing until it is closed.
type fakeDirectory struct {
	mu     sync.Mutex
	people []Identity
	err    error
	calls  int
	block  chan struct{}
}

func (d *fakeDirectory) Users(ctx context.Context, _ *Opened) ([]Identity, error) {
	d.mu.Lock()
	d.calls++
	block := d.block
	d.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Identity(nil), d.people...), d.err
}

func (d *fakeDirectory) set(names ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.people = nil
	for _, n := range names {
		d.people = append(d.people, Identity{ExternalID: "ext-" + n, Username: n, DisplayName: strings.ToUpper(n), Email: n + "@corp.example"})
	}
}

// revocations counts what the sync ends: browser sessions and live ones.
type revocations struct {
	gateway.Revoker // the rest are never called
	mu              sync.Mutex
	browser         []string
	live            []string
}

func (r *revocations) RevokeAllForUser(_ context.Context, id string) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.browser = append(r.browser, id)
	return 1, nil
}

func (r *revocations) UserRevoked(id string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.live = append(r.live, id)
	return 2
}

type syncEnv struct {
	*provisionEnv
	dir   *fakeDirectory
	rev   *revocations
	audit *audit.Log
	s     *Syncer
	op    *Opened
	now   time.Time
}

func newSyncEnv(t *testing.T, mutate func(*Config)) *syncEnv {
	t.Helper()
	pe := newProvisionEnv(t)
	e := &syncEnv{provisionEnv: pe, dir: &fakeDirectory{}, rev: &revocations{}, audit: audit.NewLog(pe.repo.db), now: time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)}
	pe.pv.Revoker = e.rev
	c := okOIDC()
	c.OIDC.Issuer = "https://kc.example/realms/zanskar"
	c.AutoProvision, c.SyncUsers = true, true
	c.DefaultRoles = []user.Role{user.RoleUser}
	if mutate != nil {
		mutate(c)
	}
	p := &Provider{Name: "kc", Type: TypeOIDC, Enabled: true}
	if err := pe.repo.Create(context.Background(), p, c); err != nil {
		t.Fatal(err)
	}
	op, err := pe.repo.Open(context.Background(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.op = op
	e.s = &Syncer{Providers: pe.repo, Provisioner: pe.pv, Sessions: e.rev, Directories: map[Type]Directory{TypeOIDC: e.dir},
		Audit: e.audit, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), now: func() time.Time { return e.now }}
	return e
}

func (e *syncEnv) run(t *testing.T, opts SyncOptions) *SyncStatus {
	t.Helper()
	st, err := e.s.Sync(context.Background(), e.op, opts)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	return st
}

func (e *syncEnv) byName(t *testing.T, name string) *user.User {
	t.Helper()
	u, err := e.users.GetByUsername(context.Background(), name)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return u
}

func (e *syncEnv) events(t *testing.T, action string) []map[string]any {
	t.Helper()
	evs, _, err := e.audit.List(context.Background(), audit.Filter{Action: action, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, ev := range evs {
		var d map[string]any
		_ = json.Unmarshal(ev.Details, &d)
		out = append(out, d)
	}
	return out
}

// TestSyncJoinersAndLeavers (ADR 0035): a person in the directory gets an
// account, linked to them, with the default roles, before any sign-in; one
// who leaves has it disabled, marked, and every session ended; one who
// comes back has it enabled again. Changes are audited, a quiet run is not.
func TestSyncJoinersAndLeavers(t *testing.T) {
	e := newSyncEnv(t, nil)
	e.dir.set("alice", "bob", "carol", "dave", "erin")
	st := e.run(t, SyncOptions{})
	if st.Listed != 5 || st.Created != 5 || !st.OK {
		t.Fatalf("first run: %+v", st)
	}
	alice := e.byName(t, "alice")
	if alice.IdPID != e.op.ID || alice.ExternalID != "ext-alice" || alice.DisplayName != "ALICE" || alice.Email != "alice@corp.example" || !alice.HasRole(user.RoleUser) || alice.PasswordHash != "" {
		t.Fatalf("alice: %+v", alice)
	}
	if got := e.events(t, audit.UserCreate); len(got) != 5 || got[0]["via"] != "directory_sync" {
		t.Fatalf("create events: %v", got)
	}

	e.now = e.now.Add(time.Minute)
	if st := e.run(t, SyncOptions{}); st.Created+st.Disabled+st.Updated != 0 {
		t.Fatalf("a quiet run changed something: %+v", st)
	}
	if n := len(e.events(t, audit.IdPSync)); n != 1 {
		t.Fatalf("a quiet run must not be audited: %d sync events", n)
	}

	// bob leaves.
	e.dir.set("alice", "carol", "dave", "erin")
	st = e.run(t, SyncOptions{})
	bob := e.byName(t, "bob")
	if st.Disabled != 1 || bob.Status != user.StatusDisabled || bob.DirectoryRemovedAt == nil {
		t.Fatalf("bob left: %+v, %s %v", st, bob.Status, bob.DirectoryRemovedAt)
	}
	if len(e.rev.browser) != 1 || e.rev.browser[0] != bob.ID || len(e.rev.live) != 1 || st.LiveSessionsEnded != 2 {
		t.Fatalf("bob's sessions: browser %v live %v", e.rev.browser, e.rev.live)
	}
	updates := e.events(t, audit.UserUpdate)
	if len(updates) != 1 || updates[0]["reason"] != "left the directory" || updates[0]["status"] != "disabled" {
		t.Fatalf("disable event: %v", updates)
	}

	// bob comes back.
	e.dir.set("alice", "bob", "carol", "dave", "erin")
	st = e.run(t, SyncOptions{})
	if bob = e.byName(t, "bob"); st.Enabled != 1 || bob.Status != user.StatusActive || bob.DirectoryRemovedAt != nil {
		t.Fatalf("bob back: %+v %s", st, bob.Status)
	}
}

// TestSyncLeavesAnAdministratorsDecision: an account an administrator
// disabled stays disabled with its person in the directory, and one they
// locked is not touched when its person leaves.
func TestSyncLeavesAnAdministratorsDecision(t *testing.T) {
	e := newSyncEnv(t, nil)
	ctx := context.Background()
	e.dir.set("alice", "bob", "carol", "dave")
	e.run(t, SyncOptions{})
	bob := e.byName(t, "bob")
	if err := e.users.Update(ctx, bob.ID, bob.DisplayName, bob.Email, user.StatusDisabled); err != nil {
		t.Fatal(err)
	}
	carol := e.byName(t, "carol")
	if err := e.users.Update(ctx, carol.ID, carol.DisplayName, carol.Email, user.StatusLocked); err != nil {
		t.Fatal(err)
	}
	e.dir.set("alice", "bob", "dave")
	st := e.run(t, SyncOptions{})
	if st.Enabled != 0 || st.Disabled != 0 {
		t.Fatalf("the sync overrode an administrator: %+v", st)
	}
	if e.byName(t, "bob").Status != user.StatusDisabled || e.byName(t, "carol").Status != user.StatusLocked {
		t.Fatal("statuses changed")
	}
}

// TestSyncAdoptsAndRefuses: with auto-provisioning off nobody is created,
// but an account an administrator made for the person (no password) is
// adopted; a local account with a password is never taken over.
func TestSyncAdoptsAndRefuses(t *testing.T) {
	e := newSyncEnv(t, func(c *Config) { c.AutoProvision = false })
	pre := e.local(t, "alice", "", user.RoleAuditor)
	e.local(t, "bob", aHash)
	e.dir.set("alice", "bob", "carol")
	st := e.run(t, SyncOptions{})
	if st.Linked != 1 || st.Created != 0 || st.NotCreated != 1 || len(st.Conflicts) != 1 || st.Conflicts[0] != "bob" {
		t.Fatalf("status: %+v", st)
	}
	if a := e.get(t, pre.ID); a.IdPID != e.op.ID || a.ExternalID != "ext-alice" || !a.HasRole(user.RoleAuditor) {
		t.Fatalf("alice adopted: %+v", a)
	}
	if b := e.byName(t, "bob"); b.IdPID != "" {
		t.Fatal("a password account must not be linked")
	}
	if _, err := e.users.GetByUsername(context.Background(), "carol"); !errors.Is(err, user.ErrNotFound) {
		t.Fatal("carol must not be created with auto-provisioning off")
	}
	if links := e.events(t, audit.UserLink); len(links) != 1 || links[0]["via"] != "directory_sync" {
		t.Fatalf("link events: %v", links)
	}
}

// TestSyncUpdatesProfile: a new name or address in the directory reaches
// the account without a sign-in.
func TestSyncUpdatesProfile(t *testing.T) {
	e := newSyncEnv(t, nil)
	e.dir.set("alice")
	e.run(t, SyncOptions{})
	e.dir.people[0].DisplayName, e.dir.people[0].Email = "Alice Liddell", "liddell@corp.example"
	if st := e.run(t, SyncOptions{}); st.Updated != 1 {
		t.Fatalf("status: %+v", st)
	}
	if a := e.byName(t, "alice"); a.DisplayName != "Alice Liddell" || a.Email != "liddell@corp.example" {
		t.Fatalf("alice: %+v", a)
	}
}

// TestSyncGuards: a directory that lists no one, or (unless forced) one
// that would take away more than half the accounts at once, disables
// nobody and says so; forcing applies it. The last active administrator is
// never disabled.
func TestSyncGuards(t *testing.T) {
	e := newSyncEnv(t, nil)
	e.dir.set("a1", "a2", "a3", "a4", "a5", "a6")
	e.run(t, SyncOptions{})

	e.dir.set()
	if st := e.run(t, SyncOptions{}); st.Held != 6 || st.Disabled != 0 || st.HeldReason != "the directory listed no one; run the sync from the console to apply" {
		t.Fatalf("empty listing: %+v", st)
	}
	e.dir.set("a1", "a2")
	st := e.run(t, SyncOptions{})
	if st.Held != 4 || st.Disabled != 0 || !strings.Contains(st.HeldReason, "would disable 4 of 6") {
		t.Fatalf("mass removal: %+v", st)
	}
	st = e.run(t, SyncOptions{Force: true, Manual: true, Actor: audit.Actor{UserID: "admin-id", IP: "203.0.113.9"}})
	if st.Disabled != 4 || st.Held != 0 {
		t.Fatalf("forced: %+v", st)
	}
	syncs := e.events(t, audit.IdPSync)
	if syncs[0]["forced"] != true {
		t.Fatalf("the forced run must say so: %v", syncs[0])
	}

	// The live 1.9.0 report (2026-10-31): a realm's only person deleted, so
	// the listing is empty. The scheduled run holds the removal back; the
	// console's "Disable 1" forces it, and the account is disabled, marked
	// and signed out instead of being held back again.
	e3 := newSyncEnv(t, nil)
	e3.dir.set("solo")
	e3.run(t, SyncOptions{})
	e3.dir.set()
	if st := e3.run(t, SyncOptions{}); st.Held != 1 || st.Disabled != 0 {
		t.Fatalf("scheduled run, empty listing: %+v", st)
	}
	if st := e3.run(t, SyncOptions{Force: true, Manual: true}); st.Held != 0 || st.Disabled != 1 || st.HeldReason != "" {
		t.Fatalf("forced run, empty listing: %+v", st)
	}
	solo := e3.byName(t, "solo")
	if solo.Status != user.StatusDisabled || solo.DirectoryRemovedAt == nil {
		t.Fatalf("solo after the forced run: %s %v", solo.Status, solo.DirectoryRemovedAt)
	}
	if len(e3.rev.browser) != 1 || e3.rev.browser[0] != solo.ID || len(e3.rev.live) != 1 {
		t.Fatalf("solo's sessions: browser %v live %v", e3.rev.browser, e3.rev.live)
	}

	// The last administrator: boss is the only admin left once x1 is made
	// a plain user, and stays active when boss leaves the directory.
	e2 := newSyncEnv(t, func(c *Config) { c.DefaultRoles = []user.Role{user.RoleAdmin} })
	e2.dir.set("boss", "x1")
	e2.run(t, SyncOptions{})
	if err := e2.users.SetRoles(context.Background(), e2.byName(t, "x1").ID, []user.Role{user.RoleUser}); err != nil {
		t.Fatal(err)
	}
	e2.dir.set("x1")
	if st := e2.run(t, SyncOptions{Force: true}); st.Disabled != 0 || st.Held != 1 || st.HeldReason != "the last active administrator is never disabled" {
		t.Fatalf("the last admin: %+v", st)
	}
	if e2.byName(t, "boss").Status != user.StatusActive {
		t.Fatal("the last admin was disabled")
	}
}

// TestSyncFailure: a directory that cannot be listed changes nothing, and
// is audited once, not on every run, until the failure changes.
func TestSyncFailure(t *testing.T) {
	e := newSyncEnv(t, nil)
	e.dir.set("alice", "bob")
	e.run(t, SyncOptions{})
	e.dir.err = errors.New("connection refused")
	for range 3 {
		st, err := e.s.Sync(context.Background(), e.op, SyncOptions{})
		if err == nil || st.OK || !strings.Contains(st.Error, "connection refused") || st.Disabled != 0 {
			t.Fatalf("failing run: %+v %v", st, err)
		}
	}
	if e.byName(t, "alice").Status != user.StatusActive {
		t.Fatal("a failed listing must change nothing")
	}
	failures := 0
	for _, d := range e.events(t, audit.IdPSync) {
		if d["error"] != nil {
			failures++
		}
	}
	if failures != 1 {
		t.Fatalf("a failure repeated must be audited once, got %d", failures)
	}
	e.dir.err = errors.New("HTTP 403")
	_, _ = e.s.Sync(context.Background(), e.op, SyncOptions{})
	failures = 0
	for _, d := range e.events(t, audit.IdPSync) {
		if d["error"] != nil {
			failures++
		}
	}
	if failures != 2 {
		t.Fatalf("a new failure must be audited, got %d", failures)
	}
}

// TestSyncOneAtATime: a second run for the same provider while one is going
// is refused, not run twice over the same accounts.
func TestSyncOneAtATime(t *testing.T) {
	e := newSyncEnv(t, nil)
	e.dir.set("alice")
	e.dir.block = make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := e.s.Sync(context.Background(), e.op, SyncOptions{})
		done <- err
	}()
	for !e.s.Running(e.op.ID) {
		time.Sleep(time.Millisecond)
	}
	if _, err := e.s.Sync(context.Background(), e.op, SyncOptions{}); !errors.Is(err, ErrSyncRunning) {
		t.Fatalf("second run: %v", err)
	}
	close(e.dir.block)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestSyncTick: a provider is listed once per interval; one without sync,
// or disabled, is never listed.
func TestSyncTick(t *testing.T) {
	e := newSyncEnv(t, func(c *Config) { c.SyncMinutes = 30 })
	e.dir.set("alice")
	ctx := context.Background()
	off := okOIDC()
	if err := e.repo.Create(ctx, &Provider{Name: "no-sync", Type: TypeOIDC, Enabled: true}, off); err != nil {
		t.Fatal(err)
	}
	dis := okOIDC()
	dis.OIDC.Issuer, dis.SyncUsers = "https://kc.example/realms/other", true
	if err := e.repo.Create(ctx, &Provider{Name: "disabled", Type: TypeOIDC, Enabled: false}, dis); err != nil {
		t.Fatal(err)
	}
	e.s.Tick(ctx)
	e.now = e.now.Add(29 * time.Minute)
	e.s.Tick(ctx)
	if e.dir.calls != 1 {
		t.Fatalf("listings within the interval: %d", e.dir.calls)
	}
	e.now = e.now.Add(2 * time.Minute)
	e.s.Tick(ctx)
	if e.dir.calls != 2 {
		t.Fatalf("listings after the interval: %d", e.dir.calls)
	}
}

// TestSyncSurvivesABadDirectory (break-it, 2026-10-30): a listing with a
// username no account can have, a person with no id, and one listed twice
// creates what it can, names the conflict, and never counts anyone twice.
// A provider pointed at another realm, where no one is the same person,
// holds every removal back rather than disabling everyone.
func TestSyncSurvivesABadDirectory(t *testing.T) {
	e := newSyncEnv(t, nil)
	e.dir.people = []Identity{
		{ExternalID: "ext-a", Username: "alice"},
		{ExternalID: "ext-a", Username: "alice-again"},
		{ExternalID: "", Username: "ghost"},
		{ExternalID: "ext-b", Username: "bad name!"},
		{ExternalID: "ext-c", Username: "carol"},
		{ExternalID: "ext-d", Username: "dave"},
		{ExternalID: "ext-e", Username: "erin"},
	}
	st := e.run(t, SyncOptions{})
	if st.Created != 4 || len(st.Conflicts) != 1 || st.Conflicts[0] != "bad name!" {
		t.Fatalf("status: %+v", st)
	}
	for _, missing := range []string{"alice-again", "ghost"} {
		if _, err := e.users.GetByUsername(context.Background(), missing); !errors.Is(err, user.ErrNotFound) {
			t.Fatalf("%s must not be created", missing)
		}
	}
	// Everyone has a new id: another realm.
	e.dir.set("alice", "carol", "dave", "erin")
	for i := range e.dir.people {
		e.dir.people[i].ExternalID = "other-" + e.dir.people[i].ExternalID
	}
	st = e.run(t, SyncOptions{})
	if st.Disabled != 0 || st.Held != 4 || len(st.Conflicts) != 4 {
		t.Fatalf("another realm: %+v", st)
	}
}

// TestSyncAdoptsPushedAccounts (break-it, 2026-10-30): a provider switched
// from SCIM to a listing finds accounts SCIM made, linked to it with no
// subject yet. The listing binds each to its person by username and keeps
// it; it must not take them for people who left and disable them.
func TestSyncAdoptsPushedAccounts(t *testing.T) {
	e := newSyncEnv(t, nil)
	ctx := context.Background()
	var pushed []string
	for _, n := range []string{"alice", "bob", "carol", "dave"} {
		u := &user.User{Username: n, DisplayName: n, Roles: []user.Role{user.RoleUser}, IdPID: e.op.ID, SCIMExternalID: "scim-" + n}
		if err := e.users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		pushed = append(pushed, u.ID)
	}
	e.dir.set("alice", "bob", "carol", "dave")
	st := e.run(t, SyncOptions{})
	if st.Linked != 4 || st.Disabled != 0 || st.Held != 0 || st.Created != 0 {
		t.Fatalf("status: %+v", st)
	}
	for i, n := range []string{"alice", "bob", "carol", "dave"} {
		u := e.byName(t, n)
		if u.ID != pushed[i] || u.ExternalID != "ext-"+n || u.Status != user.StatusActive {
			t.Fatalf("%s: %+v", n, u)
		}
	}
}

// TestSyncHealth (2026-10-31, the dashboard's integrity row): the listings
// counted, one that has not run yet, one whose last run failed, and the
// accounts held back; a provider that is not listed is not counted.
func TestSyncHealth(t *testing.T) {
	e := newSyncEnv(t, nil)
	ctx := context.Background()
	if err := e.repo.Create(ctx, &Provider{Name: "pushed", Type: TypeOIDC, Enabled: true}, okOIDC()); err != nil {
		t.Fatal(err)
	}
	h, err := e.s.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h != (SyncHealth{Listed: 1, NotRun: 1}) {
		t.Fatalf("before a run: %+v", h)
	}
	e.dir.set("alice")
	e.run(t, SyncOptions{})
	if h, _ = e.s.Health(ctx); h != (SyncHealth{Listed: 1}) {
		t.Fatalf("after a good run: %+v", h)
	}
	e.dir.err = errors.New("keycloak admin API refused the client (HTTP 403)")
	_, _ = e.s.Sync(ctx, e.op, SyncOptions{})
	if h, _ = e.s.Health(ctx); h != (SyncHealth{Listed: 1, Failing: 1}) {
		t.Fatalf("after a failed run: %+v", h)
	}
}
