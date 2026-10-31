// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/user"
)

// Directory lists the people a provider signs in, for the user sync
// (ADR 0035).
type Directory interface {
	// Users returns everyone the provider would let sign in now: enabled
	// there, and past the provider's own gates (allowed email domains),
	// each as a sign-in would assert them, ExternalID first. An error
	// means the list may be incomplete, and nothing is concluded from it.
	Users(ctx context.Context, p *Opened) ([]Identity, error)
}

// SessionRevoker ends an account's browser sessions; *auth.Sessions is one.
type SessionRevoker interface {
	RevokeAllForUser(ctx context.Context, userID string) (int64, error)
}

// SyncStatus is what one run of the sync did.
type SyncStatus struct {
	At    time.Time `json:"at"`
	OK    bool      `json:"ok"`
	Error string    `json:"error,omitempty"`
	// Listed is how many people the directory listed.
	Listed int `json:"listed"`
	// Created, Linked, Enabled and Disabled count the accounts the run
	// created, adopted (pre-created, ADR 0005 addendum), enabled again
	// after a return to the directory, and disabled after a departure.
	Created  int `json:"created"`
	Linked   int `json:"linked"`
	Updated  int `json:"updated"`
	Enabled  int `json:"enabled"`
	Disabled int `json:"disabled"`
	// NotCreated counts people with no account who were not given one,
	// because the provider does not create accounts (auto_provision).
	NotCreated int `json:"not_created"`
	// Conflicts names the people (by username, at most maxConflicts) whose
	// account could not be linked or created; see ErrAccountConflict.
	Conflicts []string `json:"conflicts,omitempty"`
	// Held counts accounts whose people have left the directory but which
	// the run did not disable, and HeldReason says why.
	Held       int    `json:"held"`
	HeldReason string `json:"held_reason,omitempty"`
	// LiveSessionsEnded counts live target sessions ended with the
	// accounts disabled.
	LiveSessionsEnded int `json:"live_sessions_ended"`
}

func (s *SyncStatus) changed() bool {
	return s.Created+s.Linked+s.Enabled+s.Disabled > 0 || s.Held > 0 || len(s.Conflicts) > 0
}

const maxConflicts = 20

// ErrSyncRunning is returned when a run for the provider is already going.
var ErrSyncRunning = errors.New("idp: a sync of this provider is already running")

// ErrNoDirectory is returned for a provider that cannot be listed.
var ErrNoDirectory = errors.New("idp: this provider cannot be listed")

// Syncer keeps a provider's accounts in line with its directory (ADR 0035).
// A run lists the directory and then, for each person: an account linked to
// them stays, and is enabled again if the sync had disabled it; otherwise a
// pre-created account is adopted, or one created when the provider creates
// accounts, as a first sign-in would. An active account whose person the
// list no longer has is disabled, and its sessions, browser and live, end.
//
// Disabling holds back, and says so, unless forced, when the directory
// listed no one or when it would disable more than half of the provider's
// active accounts at once: a directory answering short must not lock
// everyone out. It never disables the last active administrator. Only a
// list that came back whole is acted on. Group memberships are not synced.
type Syncer struct {
	Providers   *Repo
	Provisioner *Provisioner
	Sessions    SessionRevoker
	Directories map[Type]Directory
	Audit       *audit.Log
	Log         *slog.Logger
	// Timeout bounds one listing; default two minutes.
	Timeout time.Duration
	now     func() time.Time

	mu      sync.Mutex
	status  map[string]*SyncStatus
	running map[string]bool
}

func (s *Syncer) lifecycle() *Lifecycle {
	return &Lifecycle{Users: s.Provisioner.Users, Sessions: s.Sessions, Revoker: s.Provisioner.Revoker, Audit: s.Audit, Log: s.Log}
}

func (s *Syncer) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// Status returns the last run for a provider, nil before the first.
func (s *Syncer) Status(id string) *SyncStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.status[id]; st != nil {
		cp := *st
		return &cp
	}
	return nil
}

// SyncHealth is the dashboard's view of every listing (2026-10-31): counts
// only; the Identity providers page has each provider's status.
type SyncHealth struct {
	// Listed: enabled providers Zanskar lists on a schedule.
	Listed int `json:"listed"`
	// Failing: of those, how many failed their last run.
	Failing int `json:"failing"`
	// NotRun: how many have not run since the gateway started.
	NotRun int `json:"not_run"`
	// HeldBack: accounts the last runs did not disable, waiting on Sync now.
	HeldBack int `json:"held_back"`
}

// Health counts SyncHealth over the enabled providers. The listing is
// drained before any provider is opened (SQLite runs on one connection).
func (s *Syncer) Health(ctx context.Context) (SyncHealth, error) {
	var h SyncHealth
	ps, err := s.Providers.List(ctx, true)
	if err != nil {
		return h, err
	}
	for _, p := range ps {
		op, err := s.Providers.Open(ctx, p.ID)
		if err != nil {
			return h, err
		}
		if !op.Config.SyncUsers {
			continue
		}
		h.Listed++
		st := s.Status(p.ID)
		switch {
		case st == nil:
			h.NotRun++
		case !st.OK:
			h.Failing++
		}
		if st != nil {
			h.HeldBack += st.Held
		}
	}
	return h, nil
}

// Running reports whether a run for the provider is going now.
func (s *Syncer) Running(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running[id]
}

// Run syncs each enabled provider that asks for it, once its interval has
// passed since its last run, checking every minute until ctx ends.
func (s *Syncer) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		s.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick runs the providers that are due.
func (s *Syncer) Tick(ctx context.Context) {
	ps, err := s.Providers.List(ctx, true)
	if err != nil {
		s.Log.Error("user sync: list providers", "err", err)
		return
	}
	for _, p := range ps {
		op, err := s.Providers.Open(ctx, p.ID)
		if err != nil {
			s.Log.Error("user sync: open provider", "idp", p.ID, "err", err)
			continue
		}
		if !op.Config.SyncUsers {
			continue
		}
		if last := s.Status(p.ID); last != nil && s.clock().Sub(last.At) < time.Duration(op.Config.SyncMinutes)*time.Minute {
			continue
		}
		if _, err := s.Sync(ctx, op, SyncOptions{}); err != nil && !errors.Is(err, ErrSyncRunning) {
			s.Log.Warn("user sync failed", "idp", p.ID, "name", p.Name, "err", err)
		}
	}
}

// SyncOptions shape one run.
type SyncOptions struct {
	// Force applies removals the size guard would hold back; an
	// administrator asks for it from the console after reading what was
	// held.
	Force bool
	// Actor is who the audit events name: the system for a scheduled run,
	// the administrator for one asked for. An asked-for run is recorded
	// even when it changes nothing.
	Actor  audit.Actor
	Manual bool
}

// Sync runs once for p. The status is returned and kept; err is the run's
// failure, if any, also recorded in the status.
func (s *Syncer) Sync(ctx context.Context, p *Opened, opts SyncOptions) (*SyncStatus, error) {
	if opts.Actor == (audit.Actor{}) {
		opts.Actor = audit.Actor{IP: "system"}
	}
	s.mu.Lock()
	if s.running == nil {
		s.running, s.status = map[string]bool{}, map[string]*SyncStatus{}
	}
	if s.running[p.ID] {
		s.mu.Unlock()
		return nil, ErrSyncRunning
	}
	s.running[p.ID] = true
	prev := s.status[p.ID]
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.running, p.ID)
		s.mu.Unlock()
	}()

	st, err := s.sync(ctx, p, opts)
	st.At, st.OK = s.clock().UTC(), err == nil
	if err != nil {
		st.Error = err.Error()
	}
	s.mu.Lock()
	s.status[p.ID] = st
	s.mu.Unlock()
	// The log records a run that changed something, and a failure the first
	// time it happens: a directory down for a day must not write a row
	// every quarter of an hour.
	if opts.Manual || st.changed() || (err != nil && (prev == nil || prev.OK || prev.Error != st.Error)) {
		s.record(ctx, opts.Actor.Event(audit.IdPSync, "identity_provider", p.ID, outcomeOf(err), syncDetails(p, st, opts.Force)))
	}
	return st, err
}

func outcomeOf(err error) audit.Outcome {
	if err != nil {
		return audit.Failure
	}
	return audit.Success
}

func syncDetails(p *Opened, st *SyncStatus, force bool) map[string]any {
	d := map[string]any{"name": p.Name, "listed": st.Listed, "created": st.Created, "linked": st.Linked, "enabled": st.Enabled,
		"disabled": st.Disabled, "held": st.Held, "conflicts": orEmpty(st.Conflicts), "live_sessions_ended": st.LiveSessionsEnded}
	if st.HeldReason != "" {
		d["held_reason"] = st.HeldReason
	}
	if st.Error != "" {
		d["error"] = st.Error
	}
	if force {
		d["forced"] = true
	}
	return d
}

func (s *Syncer) sync(ctx context.Context, p *Opened, opts SyncOptions) (*SyncStatus, error) {
	st := &SyncStatus{}
	dir := s.Directories[p.Type]
	if dir == nil || !p.Config.SyncUsers {
		return st, ErrNoDirectory
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	lctx, cancel := context.WithTimeout(ctx, timeout)
	people, err := dir.Users(lctx, p)
	cancel()
	if err != nil {
		return st, fmt.Errorf("list the directory: %w", err)
	}
	st.Listed = len(people)
	users := s.Provisioner.Users
	linked, err := users.ListByIdP(ctx, p.ID)
	if err != nil {
		return st, err
	}
	byExternal := make(map[string]*user.User, len(linked))
	for _, u := range linked {
		byExternal[u.ExternalID] = u
	}
	sort.Slice(people, func(i, j int) bool { return people[i].Username < people[j].Username })
	seen := make(map[string]bool, len(people)) // by external id: each person once
	kept := make(map[string]bool, len(people)) // by account id: the accounts the listing accounts for
	for _, id := range people {
		if id.ExternalID == "" || seen[id.ExternalID] {
			continue
		}
		seen[id.ExternalID] = true
		if u := byExternal[id.ExternalID]; u != nil {
			kept[u.ID] = true
			if err := s.keep(ctx, p, u, id, opts.Actor, st); err != nil {
				return st, err
			}
			continue
		}
		adopted, err := s.join(ctx, p, id, opts.Actor, st)
		if err != nil {
			return st, err
		}
		if adopted != "" {
			kept[adopted] = true
		}
	}
	return st, s.leave(ctx, p, linked, kept, len(people), opts, st)
}

// keep brings a linked account in line with the directory: enabled again if
// the sync had disabled it, and the name and address the directory has.
func (s *Syncer) keep(ctx context.Context, p *Opened, u *user.User, id Identity, actor audit.Actor, st *SyncStatus) error {
	users := s.Provisioner.Users
	back, err := s.lifecycle().Return(ctx, p, u, actor, "directory_sync", "back in the directory")
	if err != nil {
		return err
	}
	if back {
		st.Enabled++
	}
	name := id.DisplayName
	if name == "" {
		name = u.DisplayName
	}
	email := firstNonEmpty(id.Email, u.Email)
	if name != u.DisplayName || email != u.Email {
		if err := users.Update(ctx, u.ID, name, email, u.Status); err != nil {
			if errors.Is(err, user.ErrDuplicate) {
				st.addConflict(u.Username)
				return nil
			}
			return err
		}
		st.Updated++
	}
	return nil
}

// join gives a person with no linked account one, as their first sign-in
// would: a pre-created account adopted, else one created when the provider
// creates accounts.
// It returns the id of an account it adopted, which the listing therefore
// accounts for.
func (s *Syncer) join(ctx context.Context, p *Opened, id Identity, actor audit.Actor, st *SyncStatus) (adopted string, err error) {
	if !user.ValidUsername(id.Username) {
		st.addConflict(id.Username)
		return "", nil
	}
	u, err := s.Provisioner.adopt(ctx, p, id)
	switch {
	case err == nil:
		st.Linked++
		s.record(ctx, actor.Event(audit.UserLink, "user", u.ID, audit.Success,
			map[string]string{"idp": p.ID, "idp_name": p.Name, "external_id": id.ExternalID, "via": "directory_sync"}))
		return u.ID, nil
	case errors.Is(err, user.ErrNotFound):
	case errors.Is(err, ErrAccountConflict):
		st.addConflict(id.Username)
		return "", nil
	case errors.Is(err, errLocked):
		return "", nil
	default:
		return "", err
	}
	if !p.Config.AutoProvision {
		st.NotCreated++
		return "", nil
	}
	u, err = s.Provisioner.create(ctx, p, id)
	if err != nil {
		if errors.Is(err, ErrAccountConflict) {
			st.addConflict(id.Username)
			return "", nil
		}
		return "", err
	}
	st.Created++
	d := map[string]any{"username": u.Username, "roles": u.Roles, "has_password": false, "via": "directory_sync",
		"idp": p.ID, "idp_name": p.Name, "external_id": id.ExternalID}
	if granted := slices.DeleteFunc(slices.Clone(u.Roles), func(r user.Role) bool { return r == user.RoleUser }); len(granted) > 0 {
		d["roles_granted"] = granted
	}
	s.record(ctx, actor.Event(audit.UserCreate, "user", u.ID, audit.Success, d))
	return "", nil
}

// leave disables the active accounts whose people the directory no longer
// lists, unless a guard holds the removals back.
func (s *Syncer) leave(ctx context.Context, p *Opened, linked []*user.User, kept map[string]bool, listed int, opts SyncOptions, st *SyncStatus) error {
	var gone []*user.User
	active := 0
	for _, u := range linked {
		if u.Status != user.StatusActive {
			continue
		}
		active++
		if !kept[u.ID] {
			gone = append(gone, u)
		}
	}
	if len(gone) == 0 {
		return nil
	}
	// Both guards hold back a scheduled run; a forced one, asked for from
	// the console after reading the reason, applies the removals (ADR 0035).
	// The empty listing ignored the force until 2026-10-31, so "Disable 1"
	// on a realm whose only person was deleted held it back again.
	switch {
	case listed == 0 && !opts.Force:
		st.Held, st.HeldReason = len(gone), "the directory listed no one; run the sync from the console to apply"
		return nil
	case !opts.Force && len(gone) > 3 && 2*len(gone) > active:
		st.Held, st.HeldReason = len(gone), fmt.Sprintf("would disable %d of %d accounts at once; run the sync from the console to apply", len(gone), active)
		return nil
	}
	life := s.lifecycle()
	for _, u := range gone {
		disabled, live, err := life.Leave(ctx, p, u, opts.Actor, "directory_sync", "left the directory", s.clock())
		switch {
		case errors.Is(err, ErrLastAdmin):
			st.Held++
			st.HeldReason = ErrLastAdmin.Error()[len("idp: "):]
			continue
		case err != nil:
			return err
		}
		if disabled {
			st.Disabled++
			st.LiveSessionsEnded += live
		}
	}
	return nil
}

func (st *SyncStatus) addConflict(username string) {
	if len(st.Conflicts) < maxConflicts {
		st.Conflicts = append(st.Conflicts, username)
	}
}

func (s *Syncer) record(ctx context.Context, e audit.Event) {
	if s.Audit == nil {
		return
	}
	if _, err := s.Audit.Record(context.WithoutCancel(ctx), e); err != nil {
		s.Log.Error("user sync: audit", "action", e.Action, "err", err)
	}
}
