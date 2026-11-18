// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"errors"
	"log/slog"
	"sync"
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

	// tried holds the recordings left awaiting an activity read that this
	// process has finished or given up on, so one whose blob is gone is
	// audited as lost once, not every minute.
	mu    sync.Mutex
	tried map[string]bool
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
	// A cloud session's recording left open for its activity's last read
	// (ADR 0050, phase C) by the process before this one: nothing will come
	// back to it, whenever the session ended.
	s.finishAwaiting(ctx, boot, "gateway restarted")
}

// Pass closes the rows this gateway has lost track of since: a row open for
// longer than Grace whose session is neither in the registry nor starting.
// It also finishes a cloud recording still awaiting its activity read past
// the grace, when no run of this gateway holds it.
func (s *Sweeper) Pass(ctx context.Context) {
	grace := s.Grace
	if grace <= 0 {
		grace = sweepGrace
	}
	now := time.Now()
	s.pass(ctx, now.Add(-grace), EndError, "the gateway lost track of this session")
	s.finishAwaiting(ctx, now.Add(-CloudActivityGrace), "the gateway lost track of this session")
}

// finishAwaiting finishes the recordings cloud sessions left open for their
// activity read (phase C) and no run of this gateway will come back to:
// those of sessions ended before cutoff that Live does not claim. The reason
// goes on the recording as a line, as the run's own read would have written
// its outcome, where storage lets a line be added; then the recording is
// finished from what storage holds, as a swept session's is. A blob storage
// cannot open (an object store takes the blob whole on close, and this one
// never closed) is lost, audited once. Left unfinished, the recording would
// never be purged by retention nor indexed (the sweep's lesson of
// 2026-11-07).
func (s *Sweeper) finishAwaiting(ctx context.Context, cutoff time.Time, why string) {
	recs, err := s.Repo.AwaitingRecordings(ctx, cutoff)
	if err != nil {
		if ctx.Err() == nil {
			s.Log.Warn("cannot list recordings awaiting their activity read", "err", err)
		}
		return
	}
	for _, rec := range recs {
		if (s.Live != nil && s.Live(rec.SessionID)) || !s.first(rec.ID) {
			continue
		}
		s.Log.Warn("finishing a cloud recording left awaiting its activity read", "session", rec.SessionID, "recording", rec.ID, "why", why)
		note := s.finishAwaitingOne(ctx, rec, "activity not read: "+why)
		s.record(ctx, audit.SessionCloudActivity, "access_session", rec.SessionID, audit.Failure,
			map[string]string{"error": why, "recording_id": rec.ID, "recording": note, "by": "the gateway's sweep of open sessions"})
	}
}

// first reports whether this process has not tried the recording yet, and
// marks it tried.
func (s *Sweeper) first(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tried == nil {
		s.tried = map[string]bool{}
	}
	if s.tried[id] {
		return false
	}
	s.tried[id] = true
	return true
}

// finishAwaitingOne writes line to the recording where it can, then finishes
// it from what storage holds; it returns the note for the event.
func (s *Sweeper) finishAwaitingOne(ctx context.Context, rec *Recording, line string) string {
	if s.Storage == nil {
		return "left unfinished: no storage to measure it"
	}
	note := ""
	switch err := recording.AppendMarker(ctx, s.Storage, rec.StorageURI, line); {
	case err == nil:
		note = "the line was written; "
	case errors.Is(err, recording.ErrNoAppend):
		note = "the storage takes no line after the close; "
	default:
		s.Log.Error("sweep: write to recording awaiting its activity read", "recording", rec.ID, "err", err)
		note = "the line could not be written: " + err.Error() + "; "
	}
	size, sum, err := recording.Measure(ctx, s.Storage, rec.StorageURI)
	if err != nil {
		s.Log.Error("sweep: measure recording", "recording", rec.ID, "err", err)
		s.record(ctx, audit.RecordingLost, "recording", rec.ID, audit.Failure,
			map[string]string{"session_id": rec.SessionID, "error": err.Error(), "by": "the gateway's sweep of open sessions"})
		return note + "lost: " + err.Error()
	}
	if err := s.Repo.FinishRecording(ctx, rec.ID, size, sum); err != nil {
		s.Log.Error("sweep: finish recording", "recording", rec.ID, "err", err)
		return note + "left unfinished: " + err.Error()
	}
	return note + "finished from what storage holds"
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
	live := s.Live
	if live == nil {
		live = func(string) bool { return false }
	}
	ended, err := s.Repo.EndAbandoned(ctx, cutoff, live, reason, detail)
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
