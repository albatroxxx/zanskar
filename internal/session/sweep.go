// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/store"
)

// EndAbandoned closes the rows still open that started before cutoff and that
// live says this gateway is not running, and returns their ids. A row stays open
// when what ends it fails: the write that closes it timing out under a stalled
// host (live, 2026-11-05: two sessions listed as live for as long as the gateway
// ran), or the gateway going away with sessions open. Nothing else ever closes
// it, and the Sessions pages and the dashboard count it as open. The gateway is
// one process (docs/architecture.md), so an open row it does not run is
// abandoned, not another gateway's.
func (r *Repo) EndAbandoned(ctx context.Context, cutoff time.Time, live func(id string) bool, reason, detail string) ([]string, error) {
	// The ids first, the cursor closed before any write: SQLite runs on one connection.
	open, err := r.openBefore(ctx, cutoff)
	if err != nil {
		return nil, err
	}
	var ended []string
	for _, id := range open {
		if live(id) {
			continue
		}
		// Only a row still open: one that closed since the list is left as it ended.
		res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE access_sessions SET ended_at = ?, end_reason = ?, end_detail = ? WHERE id = ? AND ended_at IS NULL`),
			store.TimeArg(time.Now()), reason, nullStr(detail), id)
		if err != nil {
			return ended, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			ended = append(ended, id)
		}
	}
	return ended, nil
}

// openBefore lists the ids of the rows still open that started before cutoff.
func (r *Repo) openBefore(ctx context.Context, cutoff time.Time) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT id FROM access_sessions WHERE ended_at IS NULL AND started_at < ?`), store.TimeArg(cutoff))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Sweeper ends the rows of sessions this gateway no longer runs.
type Sweeper struct {
	Repo *Repo
	// Live says whether this gateway runs the session (the registry).
	Live  func(id string) bool
	Audit *audit.Log
	Log   *slog.Logger
	// Grace is how old an open row must be before it can be abandoned: a
	// session is in the registry a moment after its row is written, and an
	// application's container takes seconds to start.
	Grace time.Duration
}

// sweepGrace is the default Grace.
const sweepGrace = 3 * time.Minute

// Startup closes what the process before this one left open: the gateway
// restarted, crashed or was killed with those sessions running. At startup
// the registry is empty, so the cutoff is now: every row opened before the
// process began is abandoned.
func (s *Sweeper) Startup(ctx context.Context, boot time.Time) {
	s.pass(ctx, boot, "gateway_restart", "the gateway restarted while this session was open")
}

// Pass closes the rows this gateway has lost track of since: a row open for
// longer than Grace whose session is not in the registry.
func (s *Sweeper) Pass(ctx context.Context) {
	grace := s.Grace
	if grace <= 0 {
		grace = sweepGrace
	}
	s.pass(ctx, time.Now().Add(-grace), EndError, "the gateway lost track of this session")
}

// Run sweeps every minute until ctx ends.
func (s *Sweeper) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Pass(ctx)
		}
	}
}

func (s *Sweeper) pass(ctx context.Context, cutoff time.Time, reason, detail string) {
	ids, err := s.Repo.EndAbandoned(ctx, cutoff, s.Live, reason, detail)
	if ctx.Err() != nil {
		return // shutting down: a pass cut short says nothing about the database
	}
	if err != nil {
		s.Log.Warn("cannot end abandoned sessions", "err", err)
	}
	for _, id := range ids {
		s.Log.Warn("ended a session left open", "session", id, "reason", reason)
		if s.Audit == nil {
			continue
		}
		d, _ := json.Marshal(map[string]string{"reason": reason, "detail": detail, "by": "the gateway's sweep of open sessions"})
		if _, err := s.Audit.Record(ctx, audit.Event{Action: audit.SessionEnd, ObjectType: "access_session", ObjectID: id, Outcome: audit.Success, Details: d}); err != nil {
			s.Log.Error("audit record failed", "action", audit.SessionEnd, "session", id, "err", err)
		}
	}
}
