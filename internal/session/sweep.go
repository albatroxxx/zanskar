// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"log/slog"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/store"
)

// Abandoned is a session row the sweep closed: enough of it for the event that
// says so.
type Abandoned struct {
	ID, UserID, TargetID string
}

// EndAbandoned closes the rows still open that started before cutoff and that
// live says this gateway is not running, and returns them. A row stays open
// when what ends it fails: the write that closes it timing out under a stalled
// host (live, 2026-11-05: two sessions listed as live for as long as the gateway
// ran), or the gateway going away with sessions open. Nothing else ever closes
// it, and the Sessions pages and the dashboard count it as open. Zanskar runs
// one gateway process per installation (docs/architecture.md, single-instance;
// the container reaper rests on the same, ADR 0017), so an open row this one
// does not run is abandoned, not another gateway's.
func (r *Repo) EndAbandoned(ctx context.Context, cutoff time.Time, live func(id string) bool, reason, detail string) ([]Abandoned, error) {
	// The rows first, the cursor closed before any write: SQLite runs on one connection.
	open, err := r.openBefore(ctx, cutoff)
	if err != nil {
		return nil, err
	}
	var ended []Abandoned
	for _, a := range open {
		if live(a.ID) {
			continue
		}
		closed, err := r.endRow(ctx, a.ID, reason, detail)
		if err != nil {
			return ended, err
		}
		if closed {
			ended = append(ended, a)
		}
	}
	return ended, nil
}

// openBefore lists the rows still open that started before cutoff.
func (r *Repo) openBefore(ctx context.Context, cutoff time.Time) ([]Abandoned, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT id, COALESCE(user_id, ''), COALESCE(target_id, '') FROM access_sessions WHERE ended_at IS NULL AND started_at < ?`), store.TimeArg(cutoff))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Abandoned
	for rows.Next() {
		var a Abandoned
		if err := rows.Scan(&a.ID, &a.UserID, &a.TargetID); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Sweeper ends the rows of sessions this gateway no longer runs.
type Sweeper struct {
	Repo *Repo
	// Live says whether this gateway runs the session: its bridge is in the
	// registry, or its row is written and its set-up still under way.
	Live func(id string) bool
	// Storage holds the recordings, to finish the one a swept session left
	// from what it holds; nil leaves it unfinished.
	Storage recording.Storage
	Audit   *audit.Log
	Log     *slog.Logger
	// Grace is how old an open row must be before it can be abandoned: a
	// session is in the registry a moment after its row is written, and Live
	// covers one still being set up.
	Grace time.Duration
}

// sweepGrace is the default Grace.
const sweepGrace = 3 * time.Minute

// sweepCloseTimeout bounds what the sweep writes once a shutdown has cut a
// pass short, the events for the rows it had closed, as connect bounds the
// writes that close a session.
const sweepCloseTimeout = 10 * time.Second

// Startup closes what the process before this one left open: the gateway
// restarted, crashed or was killed with those sessions running. At startup
// the registry is empty, so the cutoff is now: every row opened before the
// process began is abandoned.
func (s *Sweeper) Startup(ctx context.Context, boot time.Time) {
	s.pass(ctx, boot, EndGatewayRestart, "the gateway restarted while this session was open")
}

// Pass closes the rows this gateway has lost track of since: a row open for
// longer than Grace whose session is neither in the registry nor starting.
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
	ended, err := s.Repo.EndAbandoned(ctx, cutoff, s.Live, reason, detail)
	if err != nil && ctx.Err() == nil {
		s.Log.Warn("cannot end abandoned sessions", "err", err)
	}
	// What was closed is said even when a shutdown cut the pass short: a row
	// closed without its event would leave the audit log and the row
	// disagreeing for good.
	s.said(ctx, ended, reason, detail)
}

// said finishes what each closed row left, its recording, and records the
// end. It runs on when ctx has ended, under a bound of its own.
func (s *Sweeper) said(ctx context.Context, ended []Abandoned, reason, detail string) {
	if len(ended) == 0 {
		return
	}
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), sweepCloseTimeout)
		defer cancel()
	}
	for _, a := range ended {
		s.Log.Warn("ended a session left open", "session", a.ID, "reason", reason)
		details := map[string]string{"reason": reason, "detail": detail, "user_id": a.UserID, "target_id": a.TargetID, "by": "the gateway's sweep of open sessions"}
		if note := s.finishRecording(ctx, a.ID); note != "" {
			details["recording"] = note
		}
		s.record(ctx, audit.SessionEnd, "access_session", a.ID, audit.Success, details)
	}
}

// finishRecording finishes the recording a swept session left, its size and
// digest read from what storage holds, as the bridge's close would have
// written them. Retention and the output index read only finished recordings,
// so one left unfinished was kept past its policy and never searched. A blob
// storage cannot open is left unfinished and its loss audited, as a bridge
// does (B14): a playback that cannot find it has an explanation. It returns a
// note for the end event, or "" when the session has no recording to finish.
func (s *Sweeper) finishRecording(ctx context.Context, sessionID string) string {
	rec, ok, err := s.Repo.UnfinishedRecording(ctx, sessionID)
	if err != nil {
		s.Log.Error("sweep: recording of a session left open", "session", sessionID, "err", err)
		return "unknown: " + err.Error()
	}
	if !ok {
		return ""
	}
	if s.Storage == nil {
		return "left unfinished: no storage to measure it"
	}
	size, sum, err := recording.Measure(ctx, s.Storage, rec.StorageURI)
	if err != nil {
		s.Log.Error("sweep: measure recording", "recording", rec.ID, "err", err)
		s.record(ctx, audit.RecordingLost, "recording", rec.ID, audit.Failure,
			map[string]string{"session_id": sessionID, "error": err.Error(), "by": "the gateway's sweep of open sessions"})
		return "lost: " + err.Error()
	}
	if err := s.Repo.FinishRecording(ctx, rec.ID, size, sum); err != nil {
		s.Log.Error("sweep: finish recording", "recording", rec.ID, "err", err)
		return "left unfinished: " + err.Error()
	}
	return "finished from what storage holds"
}

// record writes one of the sweep's events, the gateway itself the actor, as
// the retention and image sweeps do.
func (s *Sweeper) record(ctx context.Context, action, objectType, objectID string, outcome audit.Outcome, details map[string]string) {
	if s.Audit == nil {
		return
	}
	if _, err := s.Audit.Record(ctx, audit.Actor{IP: "system"}.Event(action, objectType, objectID, outcome, details)); err != nil {
		s.Log.Error("audit record failed", "action", action, "object", objectID, "err", err)
	}
}
