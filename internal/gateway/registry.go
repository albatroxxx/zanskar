// SPDX-License-Identifier: Apache-2.0

// Package gateway holds what the protocol bridges share: the registry of
// live sessions so admins can terminate them and policy changes can end them.
package gateway

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/protocol"
)

// Live is one running bridge.
type Live struct {
	SessionID string
	UserID    string
	TargetID  string
	Protocol  string
	// PolicyID is the access policy that admitted the session, the one its
	// access_sessions row names; a label, which revocation does not key on.
	PolicyID string
	// AllowClipboard and AllowFileTransfer are the switches the session runs
	// with. A re-check ends the session when either would now be off
	// (ADR 0036): they are exfiltration controls, not limits that can wait.
	AllowClipboard    bool
	AllowFileTransfer bool
	StartedAt         time.Time
	// Tap carries the output stream for shadowing. Terminal protocols get
	// one automatically in Add; desktop sessions are shadowed through guacd
	// instead (see GuacID).
	Tap *Tap
	// GuacID is the guacd connection id of a desktop session, set by the
	// desktop bridge via SetGuacID so a watcher can join it read-only.
	GuacID string
	cancel context.CancelCauseFunc
	// ended is set by the first terminate, so two changes that withdraw
	// the same session at once count it once between them.
	ended bool
}

// Cancellation causes. Bridges read them with CancelReason to record why a
// session ended when the registry, not the peer, closed it.
var (
	ErrAdminTerminated = errors.New("session terminated by an administrator")
	ErrTargetLost      = errors.New("target left the healthy pool")
	ErrPolicyRevoked   = errors.New("access policy no longer grants this session")
	ErrGatewayRestart  = errors.New("gateway restarting")
	// ErrGrantRevoked is ErrPolicyRevoked for a just-in-time grant that an
	// administrator revoked or that expired: the same end reason, worded
	// for the person who held the grant.
	ErrGrantRevoked = errors.New("approved access revoked")
	// ErrGrantExpired ends the sessions a just-in-time grant admitted once
	// its window has passed; it reads as max_duration, the bound it is.
	ErrGrantExpired = errors.New("approved access ran out")
	// ErrTargetDisabled ends the sessions on a target an administrator
	// disabled or re-addressed; it reads as admin_terminated.
	ErrTargetDisabled = errors.New("target disabled or changed by an administrator")
	// ErrTrustLost ends the sessions on a target whose pinned host key or
	// certificate changed: the host may no longer be the one that was
	// trusted, so nothing in flight is kept.
	ErrTrustLost = errors.New("the target's host key or certificate changed")
)

// CancelReason maps a registry cancellation to an access_sessions end reason
// and a user-facing message. It returns admin_terminated for a bare cancel.
func CancelReason(ctx context.Context) (reason, msg string) {
	switch cause := context.Cause(ctx); {
	case errors.Is(cause, ErrTargetLost):
		return "target_lost", "the instance left the healthy pool"
	case errors.Is(cause, ErrPolicyRevoked):
		return "policy_revoked", "your access policy changed"
	case errors.Is(cause, ErrGrantRevoked):
		return "policy_revoked", "your approved access was revoked"
	case errors.Is(cause, ErrGrantExpired):
		return "max_duration", "your approved access ran out"
	case errors.Is(cause, ErrTargetDisabled):
		return "admin_terminated", "an administrator disabled or changed the target"
	case errors.Is(cause, ErrTrustLost):
		return "trust_lost", "the target's host key or certificate changed; an administrator must trust it again"
	case errors.Is(cause, ErrGatewayRestart):
		return "gateway_restart", "the gateway is restarting to apply a configuration change; reconnect in a moment"
	default:
		return "admin_terminated", "session ended by an administrator"
	}
}

// Registry tracks live sessions in this gateway process.
type Registry struct {
	mu   sync.Mutex
	live map[string]*Live
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{live: map[string]*Live{}} }

// Add registers a session and returns a context the bridge must run under.
func (r *Registry) Add(parent context.Context, l Live) context.Context {
	ctx, cancel := context.WithCancelCause(parent)
	l.cancel = cancel
	if l.StartedAt.IsZero() {
		l.StartedAt = time.Now()
	}
	if l.Tap == nil && protocol.Terminal(l.Protocol) {
		l.Tap = NewTap()
	}
	r.mu.Lock()
	r.live[l.SessionID] = &l
	r.mu.Unlock()
	return ctx
}

// Remove forgets a finished session and closes its tap so watchers end.
func (r *Registry) Remove(sessionID string) {
	r.mu.Lock()
	l, ok := r.live[sessionID]
	delete(r.live, sessionID)
	r.mu.Unlock()
	if ok && l.Tap != nil {
		l.Tap.Close()
	}
}

// Get returns a snapshot of a live session.
func (r *Registry) Get(sessionID string) (Live, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	l, ok := r.live[sessionID]
	if !ok {
		return Live{}, false
	}
	return *l, true
}

// Tap returns the output tap of a live terminal session, or nil.
func (r *Registry) Tap(sessionID string) *Tap {
	r.mu.Lock()
	defer r.mu.Unlock()
	if l, ok := r.live[sessionID]; ok {
		return l.Tap
	}
	return nil
}

// SetGuacID records the guacd connection id of a desktop session.
func (r *Registry) SetGuacID(sessionID, guacID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if l, ok := r.live[sessionID]; ok {
		l.GuacID = guacID
	}
}

// Terminate cancels a live session. It reports whether one was found here,
// ending already or not: the caller's question is whether this process
// holds the session, not whether it was first to end it.
func (r *Registry) Terminate(sessionID string) bool {
	r.mu.Lock()
	l, ok := r.live[sessionID]
	first := ok && !l.ended
	if first {
		l.ended = true
	}
	r.mu.Unlock()
	if first {
		l.cancel(ErrAdminTerminated)
	}
	return ok
}

// TerminateWithCause cancels a live session recording why. It reports
// whether the session was found and this call is the one that ended it; a
// session already ending (the bridge has not yet left the registry) is not
// counted again, so two changes that withdraw it at once report one end.
func (r *Registry) TerminateWithCause(sessionID string, cause error) bool {
	r.mu.Lock()
	l, ok := r.live[sessionID]
	first := ok && !l.ended
	if first {
		l.ended = true
	}
	r.mu.Unlock()
	if !first {
		return false
	}
	l.cancel(cause)
	return true
}

// TerminateTarget ends every live session on a target or instance id with
// the given cause and returns how many this call ended.
func (r *Registry) TerminateTarget(targetID string, cause error) int {
	return r.terminateWhere(func(l *Live) bool { return l.TargetID == targetID }, cause)
}

// terminateWhere ends the live sessions keep selects that are not already
// ending, and returns how many.
func (r *Registry) terminateWhere(keep func(*Live) bool, cause error) int {
	r.mu.Lock()
	var victims []*Live
	for _, l := range r.live {
		if keep(l) && !l.ended {
			l.ended = true
			victims = append(victims, l)
		}
	}
	r.mu.Unlock()
	for _, l := range victims {
		l.cancel(cause)
	}
	return len(victims)
}

// TerminateUser ends every live session of a user (account disabled, roles
// changed). Returns how many were ended.
func (r *Registry) TerminateUser(userID string) int {
	return r.terminateWhere(func(l *Live) bool { return l.UserID == userID }, ErrAdminTerminated)
}

// List snapshots live sessions.
func (r *Registry) List() []Live {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Live, 0, len(r.live))
	for _, l := range r.live {
		out = append(out, *l)
	}
	return out
}

// Count reports live sessions.
func (r *Registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.live)
}

// Waiting reports the live sessions a drain should wait for: every bridge
// in the registry, since each one has a recording and a row to finish.
func (r *Registry) Waiting() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.live)
}
