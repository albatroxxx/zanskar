// SPDX-License-Identifier: Apache-2.0

package apps

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
)

// ErrNotFound: no application session holds the presented cookie.
var ErrNotFound = errors.New("apps: session not found")

// Repo reads and writes app_sessions: the link between a browser's cookie on
// one application host and the access session it opened.
type Repo struct{ db *store.DB }

// NewRepo returns a repository over db.
func NewRepo(db *store.DB) *Repo { return &Repo{db: db} }

// Row is one application session with everything a request's check needs,
// read in one query: the row itself, the access session's end, the sign-in
// it came from, the account's standing and the application as it is now.
type Row struct {
	TokenHash     string
	SessionID     string
	AuthSessionID string
	UserID        string
	TargetID      string
	Idle          time.Duration
	ExpiresAt     *time.Time
	CreatedAt     time.Time
	LastSeenAt    time.Time

	// From the access session.
	EndedAt  *time.Time
	ClientIP string
	PolicyID string
	// From the sign-in and the account.
	AuthRevoked    bool
	AuthExpiresAt  time.Time
	AuthLastSeenAt time.Time
	UserStatus     string

	Target Application
}

// Application is the target as the proxy needs it.
type Application struct {
	Name     string
	Label    string
	Upstream string
	TLSCA    string
	Active   bool
	Deleted  bool
}

const selectRows = `SELECT a.token_hash, a.session_id, a.auth_session_id, a.user_id, a.target_id, a.idle_seconds, a.expires_at, a.created_at, a.last_seen_at,
	s.ended_at, s.client_ip, s.policy_id,
	au.revoked_at, au.expires_at, au.last_seen_at, u.status,
	t.name, t.app_label, t.app_upstream, t.tls_ca, t.status, t.deleted_at
	FROM app_sessions a
	JOIN access_sessions s ON s.id = a.session_id
	JOIN auth_sessions au ON au.id = a.auth_session_id
	JOIN users u ON u.id = a.user_id
	JOIN targets t ON t.id = a.target_id`

// Create inserts row; CreatedAt and LastSeenAt are set.
func (r *Repo) Create(ctx context.Context, row *Row) error {
	now := time.Now().UTC()
	row.CreatedAt, row.LastSeenAt = now, now
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO app_sessions
		(token_hash, session_id, auth_session_id, user_id, target_id, idle_seconds, expires_at, created_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		row.TokenHash, row.SessionID, row.AuthSessionID, row.UserID, row.TargetID, int64(row.Idle/time.Second), timeArg(row.ExpiresAt), store.TimeArg(now), store.TimeArg(now))
	return err
}

// Lookup resolves a cookie's hash to its session, or ErrNotFound.
func (r *Repo) Lookup(ctx context.Context, tokenHash string) (*Row, error) {
	rows, err := r.query(ctx, ` WHERE a.token_hash = ?`, tokenHash)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return rows[0], nil
}

// List returns every application session, open or not, oldest first.
func (r *Repo) List(ctx context.Context) ([]*Row, error) {
	return r.query(ctx, ` ORDER BY a.created_at`)
}

// Touch records activity on the session.
func (r *Repo) Touch(ctx context.Context, tokenHash string, now time.Time) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE app_sessions SET last_seen_at = ? WHERE token_hash = ?`), store.TimeArg(now.UTC()), tokenHash)
	return err
}

// Delete forgets one cookie.
func (r *Repo) Delete(ctx context.Context, tokenHash string) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM app_sessions WHERE token_hash = ?`), tokenHash)
	return err
}

// DeleteBySession forgets the cookie of an ended access session.
func (r *Repo) DeleteBySession(ctx context.Context, sessionID string) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM app_sessions WHERE session_id = ?`), sessionID)
	return err
}

// query runs selectRows with where, draining the cursor before it returns
// (single-connection SQLite).
func (r *Repo) query(ctx context.Context, where string, args ...any) ([]*Row, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(selectRows+where), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Row
	for rows.Next() {
		var (
			row                                         Row
			idle                                        int64
			expires, created, seen, ended               store.NullTime
			authRevoked, authExpires, authSeen, deleted store.NullTime
			policyID, label, upstream, ca               sql.NullString
			targetStatus                                string
		)
		if err := rows.Scan(&row.TokenHash, &row.SessionID, &row.AuthSessionID, &row.UserID, &row.TargetID, &idle, &expires, &created, &seen,
			&ended, &row.ClientIP, &policyID, &authRevoked, &authExpires, &authSeen, &row.UserStatus,
			&row.Target.Name, &label, &upstream, &ca, &targetStatus, &deleted); err != nil {
			return nil, err
		}
		row.Idle = time.Duration(idle) * time.Second
		row.ExpiresAt, row.CreatedAt, row.LastSeenAt, row.EndedAt = expires.Ptr(), created.Time, seen.Time, ended.Ptr()
		row.PolicyID = policyID.String
		row.AuthRevoked, row.AuthExpiresAt, row.AuthLastSeenAt = authRevoked.Valid, authExpires.Time, authSeen.Time
		row.Target.Label, row.Target.Upstream, row.Target.TLSCA = label.String, upstream.String, ca.String
		row.Target.Active, row.Target.Deleted = targetStatus == "active", deleted.Valid
		out = append(out, &row)
	}
	return out, rows.Err()
}

func timeArg(t *time.Time) any {
	if t == nil {
		return nil
	}
	return store.TimeArg(*t)
}
