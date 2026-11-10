// SPDX-License-Identifier: Apache-2.0

// Package apitoken keeps the API tokens administrators make for automation
// (ADR 0044): the Terraform provider, a pipeline importing the configuration
// file. A token is shown once; the gateway keeps its SHA-256, a prefix to
// tell it apart, its owner, its expiry and its last use. The auth middleware
// checks a request's token through Repo.Authenticate.
package apitoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/store"
)

// Token is an API token as it is listed: never its secret.
type Token struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Username   string     `json:"username,omitempty"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	// State is what holds now: active, expired or revoked (ADR 0047).
	State State `json:"state"`
}

// Active reports whether t stands at now: not revoked, not expired.
func (t *Token) Active(now time.Time) bool {
	return t.RevokedAt == nil && now.Before(t.ExpiresAt)
}

// ErrNotFound is a token id that names nothing.
var ErrNotFound = errors.New("apitoken: not found")

// touchEvery bounds how often a token's last use is written: a provider's
// plan makes a request per resource, and one row a minute says as much.
const touchEvery = time.Minute

// Repo stores API tokens.
type Repo struct {
	db *store.DB
	// now is the clock; tests move it.
	now func() time.Time

	mu      sync.Mutex
	touched map[string]time.Time // token id -> last use written
}

// NewRepo returns a Repo over db.
func NewRepo(db *store.DB) *Repo {
	return &Repo{db: db, now: time.Now, touched: map[string]time.Time{}}
}

// hashOf is the stored form of a token.
func hashOf(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// newSecret makes a token: the prefix and 32 random bytes, URL-safe.
func newSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return auth.TokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// prefixLen is how much of a token a list shows: "zapi_" and seven more.
const prefixLen = 12

// Create makes a token for userID that lapses after ttl and returns it with
// its secret, which is not kept.
func (r *Repo) Create(ctx context.Context, userID, name string, ttl time.Duration) (*Token, string, error) {
	secret, err := newSecret()
	if err != nil {
		return nil, "", err
	}
	now := r.now().UTC()
	t := &Token{ID: store.NewID(), UserID: userID, Name: name, Prefix: secret[:prefixLen], CreatedAt: now, ExpiresAt: now.Add(ttl), State: StateActive}
	if _, err := r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO api_tokens (id, user_id, name, token_hash, prefix, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`),
		t.ID, t.UserID, t.Name, hashOf(secret), t.Prefix, store.TimeArg(t.CreatedAt), store.TimeArg(t.ExpiresAt)); err != nil {
		return nil, "", err
	}
	return t, secret, nil
}

const cols = `t.id, t.user_id, u.username, t.name, t.prefix, t.created_at, t.expires_at, t.last_used_at, t.revoked_at`

func scan(sc interface{ Scan(...any) error }, now time.Time) (*Token, error) {
	var (
		t                               Token
		username                        sql.NullString
		created, expires, used, revoked store.NullTime
	)
	if err := sc.Scan(&t.ID, &t.UserID, &username, &t.Name, &t.Prefix, &created, &expires, &used, &revoked); err != nil {
		return nil, err
	}
	t.Username, t.CreatedAt, t.ExpiresAt, t.LastUsedAt, t.RevokedAt = username.String, created.Time, expires.Time, used.Ptr(), revoked.Ptr()
	t.State = StateOf(t.ExpiresAt, t.RevokedAt, now)
	return &t, nil
}

// List returns every token, newest first.
func (r *Repo) List(ctx context.Context) ([]*Token, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+cols+` FROM api_tokens t LEFT JOIN users u ON u.id = t.user_id ORDER BY t.created_at DESC, t.id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []*Token{}
	for rows.Next() {
		t, err := scan(rows, r.now())
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CountActive counts userID's tokens that stand now.
func (r *Repo) CountActive(ctx context.Context, userID string) (int, error) {
	all, err := r.List(ctx)
	if err != nil {
		return 0, err
	}
	n, now := 0, r.now()
	for _, t := range all {
		if t.UserID == userID && t.Active(now) {
			n++
		}
	}
	return n, nil
}

// Get returns one token.
func (r *Repo) Get(ctx context.Context, id string) (*Token, error) {
	t, err := scan(r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT `+cols+` FROM api_tokens t LEFT JOIN users u ON u.id = t.user_id WHERE t.id = ?`), id), r.now())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

// Revoke ends a token now; revoking one already revoked keeps its first
// revocation time.
func (r *Repo) Revoke(ctx context.Context, id string) (*Token, error) {
	if _, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`), store.TimeArg(r.now().UTC()), id); err != nil {
		return nil, err
	}
	r.mu.Lock()
	delete(r.touched, id)
	r.mu.Unlock()
	return r.Get(ctx, id)
}

// Authenticate is auth.TokenStore: the token's owner and id, or
// auth.ErrBadToken for a token unknown, expired or revoked. Expiry is
// compared here, not in SQL, so both engines read it the same way.
func (r *Repo) Authenticate(ctx context.Context, secret, _ string) (string, string, error) {
	var (
		id, userID       string
		expires, revoked store.NullTime
	)
	err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT id, user_id, expires_at, revoked_at FROM api_tokens WHERE token_hash = ?`), hashOf(secret)).
		Scan(&id, &userID, &expires, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", auth.ErrBadToken
	}
	if err != nil {
		return "", "", err
	}
	now := r.now()
	if revoked.Valid || !now.Before(expires.Time) {
		return "", "", auth.ErrBadToken
	}
	r.touch(ctx, id, now)
	return userID, id, nil
}

// touch writes a token's last use, at most once per touchEvery; a failed
// write is not the request's failure.
func (r *Repo) touch(ctx context.Context, id string, now time.Time) {
	r.mu.Lock()
	last, seen := r.touched[id]
	due := !seen || now.Sub(last) >= touchEvery
	if due {
		r.touched[id] = now
	}
	r.mu.Unlock()
	if due {
		_, _ = r.db.ExecContext(ctx, r.db.Rebind(`UPDATE api_tokens SET last_used_at = ? WHERE id = ?`), store.TimeArg(now.UTC()), id)
	}
}
