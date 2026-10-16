// SPDX-License-Identifier: Apache-2.0

package apps

import (
	"crypto/subtle"
	"regexp"
	"sync"
	"time"
)

// codeTTL is how long a hand-off code lives: the browser is in the middle of
// a redirect, so a minute is generous.
const codeTTL = 60 * time.Second

// stateRe is the shape of a state value the proxy made: 32 random bytes,
// URL-safe base64, so nothing else is read back out of the query.
var stateRe = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)

func validState(s string) bool { return stateRe.MatchString(s) }

// handoff is one code: who may enter which application, from where, bound to
// the state the application host gave that browser, and the path to land on,
// decided by the console. The policy is asked again when the code is
// redeemed, so nothing of its terms travels here.
type handoff struct {
	AuthSessionID string
	UserID        string
	TargetID      string
	Label         string
	State         string
	ClientIP      string
	Next          string
	ExpiresAt     time.Time
}

// codeStore keeps live codes in memory, like connect tickets: a restart only
// makes the browser ask for another.
type codeStore struct {
	mu    sync.Mutex
	codes map[string]*handoff
	now   func() time.Time
}

func newCodeStore() *codeStore { return &codeStore{codes: map[string]*handoff{}, now: time.Now} }

// issue stores g and returns the opaque code.
func (s *codeStore) issue(g handoff) (string, error) {
	tok, err := randomToken()
	if err != nil {
		return "", err
	}
	now := s.now()
	g.ExpiresAt = now.Add(codeTTL)
	s.mu.Lock()
	for k, old := range s.codes {
		if now.After(old.ExpiresAt) {
			delete(s.codes, k)
		}
	}
	s.codes[tok] = &g
	s.mu.Unlock()
	return tok, nil
}

// redeem returns the code's grant once, for the application, state and
// client it was issued to. A code presented any other way is spent.
func (s *codeStore) redeem(tok, label, state, clientIP string) (*handoff, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.codes[tok]
	if !ok {
		return nil, false
	}
	delete(s.codes, tok)
	if s.now().After(g.ExpiresAt) || g.Label != label || g.ClientIP != clientIP ||
		subtle.ConstantTimeCompare([]byte(g.State), []byte(state)) != 1 {
		return nil, false
	}
	return g, true
}
