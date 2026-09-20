// SPDX-License-Identifier: Apache-2.0

// Package ticket issues single-use, short-lived connect tickets. A ticket is
// the only credential a WebSocket upgrade carries: the browser exchanges its
// cookie session for a ticket at POST /connect, then presents the ticket in
// the WebSocket URL. Tickets live in memory; a gateway restart simply makes
// the browser ask for a new one.
package ticket

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// TTL is how long a ticket stays valid.
const TTL = 30 * time.Second

// Grant is what a ticket authorises. Everything the gateway needs to open
// the connection is decided at issue time, so the WebSocket handler never
// re-reads client-controlled input.
type Grant struct {
	UserID            string
	Username          string
	SessionID         string // browser session that requested it
	TargetID          string
	ASGID             string
	ASGInstanceID     string
	Protocol          string
	CredentialID      string
	PolicyID          string
	IdleTimeout       time.Duration
	MaxSession        time.Duration
	AllowClipboard    bool
	AllowFileTransfer bool
	ClientIP          string
	FailoverFrom      string
	// UserSecret carries a user-supplied password for the target, if the
	// credential mode requires one. Zeroed on redeem.
	UserSecret []byte
	IssuedAt   time.Time
	ExpiresAt  time.Time
}

// Errors.
var (
	ErrInvalid = errors.New("ticket: invalid or expired")
)

// Store keeps live tickets.
type Store struct {
	mu      sync.Mutex
	tickets map[string]*Grant
	now     func() time.Time
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{tickets: map[string]*Grant{}, now: time.Now}
}

// Issue stores g and returns the opaque ticket string.
func (s *Store) Issue(g Grant) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)
	now := s.now()
	g.IssuedAt, g.ExpiresAt = now, now.Add(TTL)
	s.mu.Lock()
	s.gc(now)
	s.tickets[tok] = &g
	s.mu.Unlock()
	return tok, nil
}

// Redeem returns the grant and deletes the ticket. A ticket can be redeemed
// once; the client IP must match the issuing request.
func (s *Store) Redeem(tok, clientIP string) (*Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.tickets[tok]
	if !ok {
		return nil, ErrInvalid
	}
	delete(s.tickets, tok)
	if s.now().After(g.ExpiresAt) || g.ClientIP != clientIP {
		zero(g.UserSecret)
		return nil, ErrInvalid
	}
	return g, nil
}

// Len reports live tickets (for metrics and tests).
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tickets)
}

func (s *Store) gc(now time.Time) {
	for k, g := range s.tickets {
		if now.After(g.ExpiresAt) {
			zero(g.UserSecret)
			delete(s.tickets, k)
		}
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
