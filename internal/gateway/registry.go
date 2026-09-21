// SPDX-License-Identifier: Apache-2.0

// Package gateway holds what the protocol bridges share: the registry of
// live sessions so admins can terminate them and policy changes can end them.
package gateway

import (
	"context"
	"sync"
	"time"
)

// Live is one running bridge.
type Live struct {
	SessionID string
	UserID    string
	TargetID  string
	Protocol  string
	StartedAt time.Time
	// Tap carries the output stream for shadowing. Terminal protocols get
	// one automatically in Add; desktop sessions are shadowed through guacd
	// instead (see GuacID).
	Tap *Tap
	// GuacID is the guacd connection id of a desktop session, set by the
	// desktop bridge via SetGuacID so a watcher can join it read-only.
	GuacID string
	cancel context.CancelFunc
}

// isTerminal reports whether a protocol streams bytes a Tap can fan out.
func isTerminal(protocol string) bool {
	return protocol == "ssh" || protocol == "winrm"
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
	ctx, cancel := context.WithCancel(parent)
	l.cancel = cancel
	if l.StartedAt.IsZero() {
		l.StartedAt = time.Now()
	}
	if l.Tap == nil && isTerminal(l.Protocol) {
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

// Terminate cancels a live session. It reports whether one was found.
func (r *Registry) Terminate(sessionID string) bool {
	r.mu.Lock()
	l, ok := r.live[sessionID]
	r.mu.Unlock()
	if !ok {
		return false
	}
	l.cancel()
	return true
}

// TerminateUser ends every live session of a user (account disabled, roles
// changed). Returns how many were ended.
func (r *Registry) TerminateUser(userID string) int {
	r.mu.Lock()
	var victims []*Live
	for _, l := range r.live {
		if l.UserID == userID {
			victims = append(victims, l)
		}
	}
	r.mu.Unlock()
	for _, l := range victims {
		l.cancel()
	}
	return len(victims)
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
