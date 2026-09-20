// SPDX-License-Identifier: Apache-2.0

// Package session persists access sessions (a person connected to a target)
// and their recordings. The gateway writes here; the user, admin and auditor
// APIs read from here.
package session

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
)

// EndReason values match the access_sessions.end_reason column.
const (
	EndUserExit        = "user_exit"
	EndIdleTimeout     = "idle_timeout"
	EndMaxDuration     = "max_duration"
	EndAdminTerminated = "admin_terminated"
	EndTargetLost      = "target_lost"
	EndFailover        = "failover"
	EndError           = "error"
	EndPolicyRevoked   = "policy_revoked"
)

// Session is one connection from a user to a target.
type Session struct {
	ID                    string     `json:"id"`
	UserID                string     `json:"user_id"`
	Username              string     `json:"username,omitempty"`
	TargetName            string     `json:"target_name,omitempty"`
	PolicyID              string     `json:"policy_id,omitempty"`
	TargetID              string     `json:"target_id,omitempty"`
	ASGID                 string     `json:"asg_id,omitempty"`
	ASGInstanceID         string     `json:"asg_instance_id,omitempty"`
	Protocol              string     `json:"protocol"`
	CredentialID          string     `json:"credential_id,omitempty"`
	ClientIP              string     `json:"client_ip"`
	UserAgent             string     `json:"user_agent,omitempty"`
	StartedAt             time.Time  `json:"started_at"`
	EndedAt               *time.Time `json:"ended_at,omitempty"`
	EndReason             string     `json:"end_reason,omitempty"`
	FailoverFromSessionID string     `json:"failover_from_session_id,omitempty"`
	RecordingID           string     `json:"recording_id,omitempty"`
}

// Recording is the stored capture of a session.
type Recording struct {
	ID             string     `json:"id"`
	SessionID      string     `json:"session_id"`
	Format         string     `json:"format"` // asciicast | guac
	StorageURI     string     `json:"-"`
	SizeBytes      int64      `json:"size_bytes"`
	SHA256         string     `json:"sha256,omitempty"`
	StartedAt      time.Time  `json:"started_at"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	RetentionUntil *time.Time `json:"retention_until,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// ErrNotFound is returned for unknown ids.
var ErrNotFound = errors.New("session: not found")

// Repo persists sessions and recordings.
type Repo struct {
	db *store.DB
}

// NewRepo returns a repository over db.
func NewRepo(db *store.DB) *Repo { return &Repo{db: db} }

// Start inserts a new open session. ID and StartedAt are set.
func (r *Repo) Start(ctx context.Context, s *Session) error {
	s.ID = store.NewID()
	s.StartedAt = time.Now().UTC()
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO access_sessions
		(id, user_id, policy_id, target_id, asg_id, asg_instance_id, protocol, credential_id, client_ip, user_agent, started_at, failover_from_session_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		s.ID, s.UserID, nullStr(s.PolicyID), nullStr(s.TargetID), nullStr(s.ASGID), nullStr(s.ASGInstanceID), s.Protocol,
		nullStr(s.CredentialID), s.ClientIP, s.UserAgent, store.TimeArg(s.StartedAt), nullStr(s.FailoverFromSessionID))
	return err
}

// End closes a session with a reason. Ending twice is a no-op.
func (r *Repo) End(ctx context.Context, id, reason string) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE access_sessions SET ended_at = ?, end_reason = ? WHERE id = ? AND ended_at IS NULL`),
		store.TimeArg(time.Now()), reason, id)
	return err
}

// Get returns a session.
func (r *Repo) Get(ctx context.Context, id string) (*Session, error) {
	row := r.db.QueryRowContext(ctx, r.db.Rebind(selectSessions+` WHERE s.id = ?`), id)
	return scanSession(row)
}

// Filter narrows List.
type Filter struct {
	UserID   string
	TargetID string
	OpenOnly bool
	Limit    int
	Cursor   string // started_at of the last row seen, RFC 3339
}

// List returns sessions newest first.
func (r *Repo) List(ctx context.Context, f Filter) ([]*Session, string, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	q := selectSessions + ` WHERE 1=1`
	var args []any
	if f.UserID != "" {
		q += ` AND s.user_id = ?`
		args = append(args, f.UserID)
	}
	if f.TargetID != "" {
		q += ` AND s.target_id = ?`
		args = append(args, f.TargetID)
	}
	if f.OpenOnly {
		q += ` AND s.ended_at IS NULL`
	}
	if f.Cursor != "" {
		q += ` AND s.started_at < ?`
		args = append(args, f.Cursor)
	}
	q += ` ORDER BY s.started_at DESC LIMIT ?`
	args = append(args, f.Limit+1)
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(q), args...)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()
	var out []*Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > f.Limit {
		out = out[:f.Limit]
		next = store.TimeArg(out[len(out)-1].StartedAt)
	}
	if out == nil {
		out = []*Session{}
	}
	return out, next, nil
}

// CreateRecording registers a recording for a session before bytes flow.
func (r *Repo) CreateRecording(ctx context.Context, rec *Recording) error {
	rec.ID = store.NewID()
	now := time.Now().UTC()
	rec.CreatedAt, rec.StartedAt = now, now
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO recordings (id, session_id, format, storage_uri, size_bytes, started_at, retention_until, created_at)
		VALUES (?, ?, ?, ?, 0, ?, ?, ?)`),
		rec.ID, rec.SessionID, rec.Format, rec.StorageURI, store.TimeArg(now), store.NullTime{Time: derefTime(rec.RetentionUntil), Valid: rec.RetentionUntil != nil}, store.TimeArg(now))
	return err
}

// FinishRecording records the final size and digest.
func (r *Repo) FinishRecording(ctx context.Context, id string, size int64, sha256 string) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE recordings SET size_bytes = ?, sha256 = ?, finished_at = ? WHERE id = ?`),
		size, sha256, store.TimeArg(time.Now()), id)
	return err
}

// GetRecording returns one recording.
func (r *Repo) GetRecording(ctx context.Context, id string) (*Recording, error) {
	var (
		rec                                Recording
		sha                                sql.NullString
		started, finished, retain, created store.NullTime
	)
	err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT id, session_id, format, storage_uri, size_bytes, sha256, started_at, finished_at, retention_until, created_at
		FROM recordings WHERE id = ?`), id).Scan(&rec.ID, &rec.SessionID, &rec.Format, &rec.StorageURI, &rec.SizeBytes, &sha, &started, &finished, &retain, &created)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	rec.SHA256 = sha.String
	rec.StartedAt, rec.FinishedAt, rec.RetentionUntil, rec.CreatedAt = started.Time, finished.Ptr(), retain.Ptr(), created.Time
	return &rec, nil
}

// RecordView logs that a person viewed a recording (ADR 0006).
func (r *Repo) RecordView(ctx context.Context, recordingID, userID, ip string) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO recording_views (id, recording_id, user_id, ip, viewed_at) VALUES (?, ?, ?, ?, ?)`),
		store.NewID(), recordingID, userID, ip, store.TimeArg(time.Now()))
	return err
}

const selectSessions = `SELECT s.id, s.user_id, s.policy_id, s.target_id, s.asg_id, s.asg_instance_id, s.protocol, s.credential_id,
	s.client_ip, s.user_agent, s.started_at, s.ended_at, s.end_reason, s.failover_from_session_id, rec.id, u.username, t.name
	FROM access_sessions s
	LEFT JOIN recordings rec ON rec.session_id = s.id
	LEFT JOIN users u ON u.id = s.user_id
	LEFT JOIN targets t ON t.id = s.target_id`

type scanner interface{ Scan(dest ...any) error }

func scanSession(sc scanner) (*Session, error) {
	var (
		s                                                                         Session
		policy, target, asg, inst, cred, reason, failover, recID, username, tname sql.NullString
		started, ended                                                            store.NullTime
	)
	err := sc.Scan(&s.ID, &s.UserID, &policy, &target, &asg, &inst, &s.Protocol, &cred, &s.ClientIP, &s.UserAgent,
		&started, &ended, &reason, &failover, &recID, &username, &tname)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	s.PolicyID, s.TargetID, s.ASGID, s.ASGInstanceID, s.CredentialID = policy.String, target.String, asg.String, inst.String, cred.String
	s.EndReason, s.FailoverFromSessionID, s.RecordingID = reason.String, failover.String, recID.String
	s.Username, s.TargetName = username.String, tname.String
	s.StartedAt, s.EndedAt = started.Time, ended.Ptr()
	return &s, nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
