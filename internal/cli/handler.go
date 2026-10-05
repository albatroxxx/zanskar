// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/user"
)

const (
	// freshFor is how long a proved authenticator code keeps the command
	// line open, counted from the code or from the last command.
	freshFor = 15 * time.Minute
	// maxFails wrong codes close the command line for this sign-in for
	// lockFor; the sign-in itself is untouched.
	maxFails = 5
	lockFor  = 15 * time.Minute
	// confirmFor is how long a confirmation prompt stays answerable.
	confirmFor = 2 * time.Minute
	// perMinute bounds lines per sign-in.
	perMinute = 60
)

// MFA is the part of the authenticator store the command line uses.
type MFA interface {
	Enrolled(ctx context.Context, userID string) (bool, error)
	Verify(ctx context.Context, userID, code string) (bool, error)
}

// Handler serves the console's command line.
type Handler struct {
	Sessions *auth.Sessions
	MFA      MFA
	Audit    *audit.Log
	Log      *slog.Logger

	now   func() time.Time
	mux   http.Handler
	cmds  []*command
	mu    sync.Mutex
	state map[string]*signIn
}

// signIn is the command line's memory of one console sign-in. It is kept in
// memory on purpose: a restart simply asks for a fresh code again.
type signIn struct {
	lastUse     time.Time
	fails       int
	lockedUntil time.Time
	pending     *pendingConfirm
	recent      []time.Time
}

type pendingConfirm struct {
	line    string
	expires time.Time
}

// Register mounts the routes and keeps the router: commands are dispatched
// through it at request time, when every route is registered.
func (h *Handler) Register(mux *http.ServeMux) {
	h.mux = mux
	h.cmds = commands()
	if h.now == nil {
		h.now = time.Now
	}
	h.state = map[string]*signIn{}
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/admin/cli", admin(http.HandlerFunc(h.status)))
	mux.Handle("POST /api/v1/admin/cli/unlock", admin(http.HandlerFunc(h.unlock)))
	mux.Handle("POST /api/v1/admin/cli", admin(http.HandlerFunc(h.exec)))
}

// signInFor returns the state for a sign-in, creating it, and drops state
// for sign-ins idle long enough to be over anyway.
func (h *Handler) signInFor(id string, now time.Time) *signIn {
	if len(h.state) > 256 {
		for k, s := range h.state {
			if now.Sub(s.lastUse) > 13*time.Hour && now.After(s.lockedUntil) {
				delete(h.state, k)
			}
		}
	}
	s := h.state[id]
	if s == nil {
		s = &signIn{}
		h.state[id] = s
	}
	return s
}

func (h *Handler) fresh(p *auth.Principal, s *signIn, now time.Time) bool {
	last := p.Session.MFAAt
	if s.lastUse.After(last) {
		last = s.lastUse
	}
	return !last.IsZero() && now.Sub(last) <= freshFor
}

type statusReply struct {
	Enabled     bool `json:"enabled"`
	Unlocked    bool `json:"unlocked"`
	MFAEnrolled bool `json:"mfa_enrolled"`
	IdleMinutes int  `json:"idle_minutes"`
}

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	enrolled, err := h.MFA.Enrolled(r.Context(), p.User.ID)
	if err != nil {
		h.Log.Error("cli: authenticator lookup", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	now := h.now()
	h.mu.Lock()
	unlocked := h.fresh(p, h.signInFor(p.Session.ID, now), now)
	h.mu.Unlock()
	httpx.WriteJSON(w, http.StatusOK, statusReply{Enabled: true, Unlocked: unlocked && enrolled, MFAEnrolled: enrolled, IdleMinutes: int(freshFor / time.Minute)})
}

func (h *Handler) unlock(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	var in struct {
		Code string `json:"code"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	now := h.now()
	h.mu.Lock()
	s := h.signInFor(p.Session.ID, now)
	locked := now.Before(s.lockedUntil)
	h.mu.Unlock()
	if locked {
		httpx.WriteError(w, http.StatusTooManyRequests, "cli_locked", "too many wrong codes; the command line is closed for this sign-in for a while")
		return
	}
	recovery, err := h.MFA.Verify(r.Context(), p.User.ID, in.Code)
	switch {
	case errors.Is(err, auth.ErrTOTPNotEnrolled):
		h.record(r, "cli.unlock", audit.Failure, map[string]any{"reason": "no authenticator enrolled"})
		httpx.WriteError(w, http.StatusConflict, "mfa_not_enrolled", "enrol an authenticator first: the command line asks for a code from it")
		return
	case errors.Is(err, auth.ErrTOTPBadCode):
		h.mu.Lock()
		s.fails++
		closed := s.fails >= maxFails
		if closed {
			s.lockedUntil, s.fails = now.Add(lockFor), 0
		}
		h.mu.Unlock()
		h.record(r, "cli.unlock", audit.Failure, map[string]any{"reason": "wrong code", "closed": closed})
		// 422, not 401: to the console a 401 means the sign-in itself has ended.
		httpx.WriteError(w, http.StatusUnprocessableEntity, "bad_code", "that code is not right")
		return
	case err != nil:
		h.Log.Error("cli: verify code", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if err := h.Sessions.MarkMFAProved(r.Context(), p.Session.ID); err != nil {
		h.Log.Error("cli: record fresh code", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	h.mu.Lock()
	s.fails, s.lastUse = 0, now
	h.mu.Unlock()
	h.record(r, "cli.unlock", audit.Success, map[string]any{"recovery_code_used": recovery})
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"unlocked": true})
}

// execReply is what the console prints.
type execReply struct {
	Status string `json:"status"` // ok, error, confirm, cancelled
	Lines  []Line `json:"lines"`
	Expect string `json:"expect,omitempty"`
}

// Results recorded in the cli.command audit event.
const (
	resultOK        = "ok"
	resultConfirm   = "confirm_requested"
	resultCancelled = "cancelled"
	resultInvalid   = "invalid"
	resultUnknown   = "unknown"
	resultDenied    = "denied"
	resultError     = "error"
	resultLocked    = "locked"
)

func (h *Handler) exec(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	var in struct {
		Line    string `json:"line"`
		Confirm string `json:"confirm"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	line := strings.TrimSpace(in.Line)
	if len(line) > maxLine || len(in.Confirm) > maxLine {
		httpx.BadRequest(w, errTooLong.Error())
		return
	}
	now := h.now()
	h.mu.Lock()
	s := h.signInFor(p.Session.ID, now)
	fresh := h.fresh(p, s, now)
	limited := !allow(s, now)
	h.mu.Unlock()
	if limited {
		httpx.WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many commands; wait a moment")
		return
	}
	if !fresh {
		h.audit(r, line, "", resultLocked, nil)
		httpx.WriteError(w, http.StatusForbidden, "cli_locked", "enter a code from your authenticator to use the command line")
		return
	}
	reply, name, result, calls := h.run(r, s, line, in.Confirm, now)
	h.mu.Lock()
	s.lastUse = now
	h.mu.Unlock()
	h.audit(r, line, name, result, calls)
	httpx.WriteJSON(w, http.StatusOK, reply)
}

// allow is a sliding one-minute window of lines. Called with h.mu held.
func allow(s *signIn, now time.Time) bool {
	kept := s.recent[:0]
	for _, t := range s.recent {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	s.recent = kept
	if len(s.recent) >= perMinute {
		return false
	}
	s.recent = append(s.recent, now)
	return true
}

func (h *Handler) run(r *http.Request, s *signIn, line, confirm string, now time.Time) (execReply, string, string, []apiCall) {
	o := &out{}
	fail := func(result, format string, a ...any) (execReply, string, string, []apiCall) {
		o.add(styleError, "%s", sentence(fmt.Sprintf(format, a...)))
		return execReply{Status: "error", Lines: o.lines}, "", result, nil
	}
	words, err := tokenize(line)
	if err != nil {
		return fail(resultInvalid, "%s", err.Error())
	}
	c, rest := find(h.cmds, words)
	if c == nil {
		o.add(styleError, "Unknown command %q. This is not a shell: only Zanskar commands run here. Type help to list them.", words[0])
		return execReply{Status: "error", Lines: o.lines}, "", resultUnknown, nil
	}
	args, err := parseArgs(c, rest)
	if err != nil {
		o.add(styleError, "%s", sentence(err.Error()))
		return execReply{Status: "error", Lines: o.lines}, c.name, resultInvalid, nil
	}
	x := &run{parsed: args, out: o, now: now, resolved: map[string]string{}, cmds: h.cmds,
		api: &caller{mux: h.mux, ctx: r.Context(), remoteAddr: r.RemoteAddr}}
	result := resultOK
	if c.plan != nil {
		h.mu.Lock()
		pend := s.pending
		s.pending = nil
		h.mu.Unlock()
		// The plan runs again on the confirming request, so what is shown
		// and what is checked are current: a session that ended in the
		// meantime is not "terminated" on stale information.
		prompt, expect, err := c.plan(x)
		if err != nil {
			return h.failed(x, c, err)
		}
		if confirm == "" {
			h.mu.Lock()
			s.pending = &pendingConfirm{line: line, expires: now.Add(confirmFor)}
			h.mu.Unlock()
			o.add(styleWarn, "%s", prompt)
			o.text("Type %s to confirm, or anything else to cancel.", expect)
			return execReply{Status: "confirm", Lines: o.lines, Expect: expect}, c.name, resultConfirm, x.api.calls
		}
		if pend == nil || pend.line != line || now.After(pend.expires) {
			o.add(styleError, "Nothing to confirm: run the command again.")
			return execReply{Status: "error", Lines: o.lines}, c.name, resultInvalid, x.api.calls
		}
		if confirm != expect {
			o.add(styleMuted, "Cancelled.")
			return execReply{Status: "cancelled", Lines: o.lines}, c.name, resultCancelled, x.api.calls
		}
	}
	if err := c.exec(x); err != nil {
		return h.failed(x, c, err)
	}
	return execReply{Status: "ok", Lines: o.lines}, c.name, result, x.api.calls
}

func (h *Handler) failed(x *run, c *command, err error) (execReply, string, string, []apiCall) {
	var (
		ue errUsage
		ae *apiError
	)
	result := resultError
	switch {
	case errors.As(err, &ue):
		x.out.add(styleError, "%s", sentence(ue.msg))
		result = resultInvalid
	case errors.As(err, &ae) && ae.Status == http.StatusForbidden:
		x.out.add(styleError, "Not allowed: %s", ae.Error())
		result = resultDenied
	case errors.As(err, &ae):
		x.out.add(styleError, "%s", sentence(ae.Error()))
	default:
		h.Log.Error("cli: command failed", "command", c.name, "err", err)
		x.out.add(styleError, "The command failed; the gateway log has the details.")
	}
	return execReply{Status: "error", Lines: x.out.lines}, c.name, result, x.api.calls
}

// sentence starts a message with a capital letter, the way the console
// shows messages; Go error strings start in lower case.
func sentence(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if n == 0 {
		return s
	}
	return string(unicode.ToUpper(r)) + s[n:]
}

// audit records one line. Every line is recorded, read-only ones too, so the
// log shows what an administrator looked at from the command line as well as
// what they changed; the API's own event for a change sits just before it.
func (h *Handler) audit(r *http.Request, line, name, result string, calls []apiCall) {
	outcome := audit.Success
	switch result {
	case resultOK, resultConfirm, resultCancelled:
	default:
		outcome = audit.Failure
	}
	details := map[string]any{"line": line, "result": result}
	if name != "" {
		details["command"] = name
	}
	if len(calls) > 0 {
		details["calls"] = calls
	}
	h.record(r, "cli.command", outcome, details)
}

func (h *Handler) record(r *http.Request, action string, outcome audit.Outcome, details any) {
	if h.Audit == nil {
		return
	}
	actor := audit.Actor{IP: auth.ClientIP(r)}
	if p, ok := auth.FromContext(r.Context()); ok {
		actor.UserID = p.User.ID
	}
	if _, err := h.Audit.Record(r.Context(), actor.Event(action, "cli", "", outcome, details)); err != nil {
		h.Log.Error("audit record failed", "action", action, "err", err)
	}
}
