// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"maps"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/ticket"
)

// sessionRun is one session after its websocket upgrade, which the four
// bridges (SSH, WinRM, desktop, database) live through the same way: the row
// is written before anything can fail, so a failed dial still leaves a trace;
// the recording is registered before a byte flows, or the session is refused;
// the session is in the registry while its bridge runs, so it can be
// shadowed, terminated and revoked; and its end is audited with its reason.
type sessionRun struct {
	h     *Handler
	r     *http.Request
	ws    *websocket.Conn
	g     *ticket.Grant
	ep    *endpoint
	actor audit.Actor
	s     *session.Session
	// startDetails are added to the session.start event.
	startDetails map[string]any
	// tell, when set, tells the client why the session is refused before the
	// socket closes: the desktop's client reads a guacamole error
	// instruction, not the close reason.
	tell func(msg string)
}

// closeTimeout is the default bound on one closing write (Handler.CloseTimeout).
// The bridges bound their closing frames to 2 s and recording storage its
// deletes to 10 s; a database write gets the longer of the two.
const closeTimeout = 10 * time.Second

// frameTimeout bounds one closing websocket frame, as the bridges bound
// theirs.
const frameTimeout = 2 * time.Second

// detach keeps ctx's values, such as the request id the logs carry, but not
// its cancellation, and bounds what follows to d: for writes that must happen
// although the client that asked for them has gone, without a stuck database
// holding the goroutine for ever.
func detach(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), d)
}

// closing returns the context for one write that closes the session.
func (run *sessionRun) closing() (context.Context, context.CancelFunc) {
	d := run.h.CloseTimeout
	if d <= 0 {
		d = closeTimeout
	}
	return detach(run.r.Context(), d)
}

// startRun writes the session's row. When it cannot, the socket is closed and
// ok is false.
func (h *Handler) startRun(r *http.Request, ws *websocket.Conn, g *ticket.Grant, ep *endpoint, ip string) (*sessionRun, bool) {
	s := &session.Session{UserID: g.UserID, PolicyID: g.PolicyID, TargetID: ep.TargetID, ASGID: ep.ASGID, ASGInstanceID: ep.ASGInstanceID,
		Protocol: g.Protocol, CredentialID: g.CredentialID, ClientIP: ip, UserAgent: r.UserAgent(), FailoverFromSessionID: g.FailoverFrom}
	if err := h.Sessions.Start(r.Context(), s); err != nil {
		h.Log.Error("start session", "err", err)
		_ = ws.Close(websocket.StatusInternalError, "could not start session")
		return nil, false
	}
	run := &sessionRun{h: h, r: r, ws: ws, g: g, ep: ep, actor: actorFor(g.UserID, ip), s: s}
	// The failover route closed the session this one replaces, as
	// target_lost, before it issued the ticket; this only catches a row that
	// close missed.
	if g.FailoverFrom != "" {
		run.endRow(g.FailoverFrom, session.EndFailover)
	}
	return run, true
}

// endRow closes a session's row.
func (run *sessionRun) endRow(id, reason string) {
	ctx, cancel := run.closing()
	defer cancel()
	if err := run.h.Sessions.End(ctx, id, reason); err != nil {
		run.h.Log.Error("end session", "session", id, "err", err)
	}
}

// end closes the session's row and audits its end. With a message, the client
// is told why and the socket closes as a policy violation, the close the
// console shows a reason for.
func (run *sessionRun) end(reason, msg string) {
	run.endRow(run.s.ID, reason)
	run.h.record(run.r, run.actor.Event(audit.SessionEnd, "access_session", run.s.ID, audit.Success, map[string]string{"reason": reason, "target_id": run.ep.LiveKey}))
	if msg != "" {
		if run.tell != nil {
			run.tell(msg)
		}
		_ = run.ws.Close(websocket.StatusPolicyViolation, msg)
	}
}

// recorder is what a run needs of a recording once its bridge returns.
type recorder interface {
	Close() (size int64, digest string, err error)
}

// asciicast starts the session's terminal recording; see register.
func (run *sessionRun) asciicast(title string, cols, rows int) (*recording.Asciicast, *session.Recording, bool) {
	rec, uri, err := recording.NewAsciicast(run.r.Context(), run.h.Storage, run.s.ID+".cast", recording.Header{Width: cols, Height: rows, Title: title,
		Env: map[string]string{"ZANSKAR_SESSION": run.s.ID}})
	if err != nil {
		run.recordingFailed(err)
		return nil, nil, false
	}
	row, ok := run.register(rec, "asciicast", uri)
	return rec, row, ok
}

// guacStream starts the session's desktop recording; see register.
func (run *sessionRun) guacStream() (*recording.GuacStream, *session.Recording, bool) {
	rec, uri, err := recording.NewGuacStream(run.r.Context(), run.h.Storage, run.s.ID+".guac")
	if err != nil {
		run.recordingFailed(err)
		return nil, nil, false
	}
	row, ok := run.register(rec, "guac", uri)
	return rec, row, ok
}

// recordingFailed refuses a session whose recording could not be started: no
// session runs unrecorded.
func (run *sessionRun) recordingFailed(err error) {
	run.h.Log.Error("start recording", "session", run.s.ID, "err", err)
	run.end(session.EndError, "recording could not be started; session refused")
}

// register writes the recording's row and audits the session's start. When
// the row cannot be written, the recording is closed and the session refused.
func (run *sessionRun) register(rec recorder, format, uri string) (*session.Recording, bool) {
	row := &session.Recording{SessionID: run.s.ID, Format: format, StorageURI: uri, RetentionUntil: retentionUntil(run.g)}
	if err := run.h.Sessions.CreateRecording(run.r.Context(), row); err != nil {
		run.h.Log.Error("register recording", "session", run.s.ID, "err", err)
		_, _, _ = rec.Close()
		run.end(session.EndError, "recording could not be registered; session refused")
		return nil, false
	}
	details := map[string]any{"target_id": run.ep.LiveKey, "protocol": run.g.Protocol, "policy_id": run.g.PolicyID, "recording_id": row.ID}
	maps.Copy(details, run.startDetails)
	run.h.record(run.r, run.actor.Event(audit.SessionStart, "access_session", run.s.ID, audit.Success, details))
	return row, true
}

// live puts the session in the registry and returns the context its bridge
// runs under, which a terminate or a revocation cancels; call done when the
// bridge returns.
func (run *sessionRun) live() (ctx context.Context, done func()) {
	ctx = run.h.Registry.Add(run.r.Context(), gateway.Live{SessionID: run.s.ID, UserID: run.g.UserID, TargetID: run.ep.LiveKey,
		Protocol: run.g.Protocol, PolicyID: run.g.PolicyID})
	return ctx, func() { run.h.Registry.Remove(run.s.ID) }
}

// finish closes the recording once the bridge returns and ends the session
// with the bridge's reason.
func (run *sessionRun) finish(rec recorder, row *session.Recording, reason string, err error) {
	run.finishRecording(rec, row)
	if err != nil {
		run.h.Log.Warn("bridge ended with error", "session", run.s.ID, "protocol", run.g.Protocol, "err", err)
	}
	if reason == "" {
		reason = session.EndError
	}
	run.end(reason, "")
	_ = run.ws.Close(websocket.StatusNormalClosure, reason)
}

// finishRecording closes the session's recording and records its size and
// digest. A recording whose close failed (its upload, say) is not marked
// finished: its row keeps finished_at empty, as the storage documents, and
// the loss is audited as recording.lost, so a playback that cannot find it
// has an explanation. It used to be marked finished with size 0 and no
// digest, which read as an empty recording (B14).
func (run *sessionRun) finishRecording(rec recorder, row *session.Recording) {
	size, sum, err := rec.Close()
	if err != nil {
		run.h.Log.Error("close recording", "session", run.s.ID, "err", err)
		run.h.record(run.r, run.actor.Event(audit.RecordingLost, "recording", row.ID, audit.Failure, map[string]string{"session_id": run.s.ID, "error": err.Error()}))
		return
	}
	ctx, cancel := run.closing()
	defer cancel()
	if err := run.h.Sessions.FinishRecording(ctx, row.ID, size, sum); err != nil {
		run.h.Log.Error("finish recording", "session", run.s.ID, "err", err)
	}
}
