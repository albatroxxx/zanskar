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
	cancel    context.CancelFunc
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
	r.mu.Lock()
	r.live[l.SessionID] = &l
	r.mu.Unlock()
	return ctx
}

// Remove forgets a finished session.
func (r *Registry) Remove(sessionID string) {
	r.mu.Lock()
	delete(r.live, sessionID)
	r.mu.Unlock()
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
