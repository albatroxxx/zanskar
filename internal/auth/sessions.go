// SPDX-License-Identifier: Apache-2.0

// Package auth authenticates people to Zanskar: browser sessions, CSRF,
// password login, TOTP second factor and the middleware that guards routes.
// Authentication of Zanskar to targets is a different concern (ADR 0005) and
// lives in the credentials and gateway packages.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
)

// CookieName is the browser session cookie.
const CookieName = "zanskar_session"

// Session is a browser login. The token itself is never stored; only its
// SHA-256 is, so a database read cannot be replayed as a cookie.
type Session struct {
	ID          string
	UserID      string
	MFAVerified bool
	IP          string
	UserAgent   string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	LastSeenAt  time.Time
}

// Errors.
var (
	ErrNoSession = errors.New("auth: no valid session")
)

// Sessions creates, looks up and revokes browser sessions.
type Sessions struct {
	db      *store.DB
	csrfKey []byte
	// AbsoluteTTL bounds a login regardless of activity.
	AbsoluteTTL time.Duration
	// IdleTTL ends a login after inactivity.
	IdleTTL time.Duration
	// SecureCookie sets the Secure flag; false only for plain-HTTP loopback dev.
	SecureCookie bool
	now          func() time.Time
}

// NewSessions returns a manager. csrfKey should be 32 bytes derived from the
// master key; CSRF tokens are HMACs over the session id under that key.
func NewSessions(db *store.DB, csrfKey []byte, secureCookie bool) *Sessions {
	return &Sessions{
		db:           db,
		csrfKey:      csrfKey,
		AbsoluteTTL:  12 * time.Hour,
		IdleTTL:      60 * time.Minute,
		SecureCookie: secureCookie,
		now:          time.Now,
	}
}

// Create starts a session and returns the opaque token for the cookie.
func (s *Sessions) Create(ctx context.Context, userID, ip, userAgent string, mfaVerified bool) (string, *Session, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	now := s.now().UTC()
	sess := &Session{
		ID:          store.NewID(),
		UserID:      userID,
		MFAVerified: mfaVerified,
		IP:          ip,
		UserAgent:   truncate(userAgent, 512),
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.AbsoluteTTL),
		LastSeenAt:  now,
	}
	_, err := s.db.ExecContext(ctx, s.db.Rebind(`INSERT INTO auth_sessions
		(id, user_id, token_hash, ip, user_agent, mfa_verified, created_at, expires_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		sess.ID, userID, hashToken(token), ip, sess.UserAgent, mfaVerified,
		store.TimeArg(now), store.TimeArg(sess.ExpiresAt), store.TimeArg(now))
	if err != nil {
		return "", nil, err
	}
	return token, sess, nil
}

// Lookup resolves a cookie token to a live session and refreshes last_seen_at.
// Expired, idle or revoked sessions return ErrNoSession.
func (s *Sessions) Lookup(ctx context.Context, token string) (*Session, error) {
	if token == "" {
		return nil, ErrNoSession
	}
	var (
		sess                        Session
		revoked, created, exp, seen store.NullTime
	)
	err := s.db.QueryRowContext(ctx, s.db.Rebind(`SELECT id, user_id, ip, user_agent, mfa_verified, created_at, expires_at, last_seen_at, revoked_at
		FROM auth_sessions WHERE token_hash = ?`), hashToken(token)).
		Scan(&sess.ID, &sess.UserID, &sess.IP, &sess.UserAgent, &sess.MFAVerified, &created, &exp, &seen, &revoked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoSession
		}
		return nil, err
	}
	sess.CreatedAt, sess.ExpiresAt, sess.LastSeenAt = created.Time, exp.Time, seen.Time
	now := s.now().UTC()
	if revoked.Valid || now.After(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) > s.IdleTTL {
		return nil, ErrNoSession
	}
	// Throttle the write: refreshing on every request would make each page
	// load a database write for no security gain.
	if now.Sub(sess.LastSeenAt) > time.Minute {
		if _, err := s.db.ExecContext(ctx, s.db.Rebind(`UPDATE auth_sessions SET last_seen_at = ? WHERE id = ?`), store.TimeArg(now), sess.ID); err != nil {
			return nil, err
		}
		sess.LastSeenAt = now
	}
	return &sess, nil
}

// MarkMFAVerified upgrades a session after a successful second factor.
func (s *Sessions) MarkMFAVerified(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.db.Rebind(`UPDATE auth_sessions SET mfa_verified = TRUE WHERE id = ?`), id)
	return err
}

// Revoke ends one session.
func (s *Sessions) Revoke(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.db.Rebind(`UPDATE auth_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`), store.TimeArg(s.now()), id)
	return err
}

// RevokeAllForUser ends every live session of a user, for example after a
// password change or an admin disabling the account.
func (s *Sessions) RevokeAllForUser(ctx context.Context, userID string) (int64, error) {
	res, err := s.db.ExecContext(ctx, s.db.Rebind(`UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`), store.TimeArg(s.now()), userID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteExpired removes sessions that can never be used again. Run periodically.
func (s *Sessions) DeleteExpired(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, s.db.Rebind(`DELETE FROM auth_sessions WHERE expires_at < ? OR revoked_at IS NOT NULL`), store.TimeArg(s.now().Add(-24*time.Hour)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CSRFToken derives the token for a session. It is stateless: the same
// session always yields the same token, and it is useless without the cookie.
func (s *Sessions) CSRFToken(sessionID string) string {
	mac := hmac.New(sha256.New, s.csrfKey)
	mac.Write([]byte("csrf:" + sessionID))
	return hex.EncodeToString(mac.Sum(nil))
}

// CheckCSRF verifies a presented token in constant time.
func (s *Sessions) CheckCSRF(sessionID, presented string) bool {
	want := s.CSRFToken(sessionID)
	return subtle.ConstantTimeCompare([]byte(want), []byte(presented)) == 1
}

// SetCookie writes the session cookie. SameSite=Strict means the browser
// never sends it on cross-site navigations or requests.
func (s *Sessions) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure comes from config; false only on loopback dev
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookie,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.AbsoluteTTL / time.Second),
	})
}

// ClearCookie removes the session cookie.
func (s *Sessions) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- same as SetCookie
		Name: CookieName, Value: "", Path: "/", HttpOnly: true, Secure: s.SecureCookie,
		SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
