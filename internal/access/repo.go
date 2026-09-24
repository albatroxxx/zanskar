// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
)

// Repo reads and writes access requests.
type Repo struct {
	db *store.DB
}

// NewRepo returns a repository over db.
func NewRepo(db *store.DB) *Repo { return &Repo{db: db} }

const cols = `id, user_id, policy_id, target_id, asg_id, protocol, reason, requested_minutes,
	status, approver_user_id, decision_note, decided_at, expires_at, created_at, updated_at`

// Create inserts req as a pending request, setting ID, status and timestamps.
func (r *Repo) Create(ctx context.Context, req *Request) error {
	now := time.Now().UTC()
	req.ID = store.NewID()
	req.Status = StatusPending
	req.CreatedAt, req.UpdatedAt = now, now
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO access_requests (`+cols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		req.ID, req.UserID, nullStr(req.PolicyID), nullStr(req.TargetID), nullStr(req.ASGID), req.Protocol, req.Reason, req.RequestedMinutes,
		string(req.Status), nullStr(req.ApproverUserID), req.DecisionNote, timeArg(req.DecidedAt), timeArg(req.ExpiresAt), store.TimeArg(now), store.TimeArg(now))
	return err
}

// Get returns one request by id.
func (r *Repo) Get(ctx context.Context, id string) (*Request, error) {
	row := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT `+cols+` FROM access_requests WHERE id = ?`), id)
	return scan(row)
}

// ListByUser returns a user's own requests, newest first.
func (r *Repo) ListByUser(ctx context.Context, userID string) ([]*Request, error) {
	return r.query(ctx, `WHERE user_id = ? ORDER BY created_at DESC LIMIT 500`, userID)
}

// List returns requests for the admin queue, newest first; status "" means all.
func (r *Repo) List(ctx context.Context, status Status) ([]*Request, error) {
	if status == "" {
		return r.query(ctx, `ORDER BY created_at DESC LIMIT 500`)
	}
	return r.query(ctx, `WHERE status = ? ORDER BY created_at DESC LIMIT 500`, string(status))
}

// ActiveForUser returns a user's approved, unexpired grants.
func (r *Repo) ActiveForUser(ctx context.Context, userID string, now time.Time) ([]*Request, error) {
	return r.query(ctx, `WHERE user_id = ? AND status = ? AND expires_at > ? ORDER BY expires_at`,
		userID, string(StatusApproved), store.TimeArg(now))
}

// Decide moves a pending request to approved or denied. expiresAt is set on
// approval (nil on denial). It fails with ErrState if the request is no longer
// pending, ErrNotFound if it does not exist.
func (r *Repo) Decide(ctx context.Context, id, approverID string, status Status, note string, expiresAt *time.Time) (*Request, error) {
	now := time.Now().UTC()
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE access_requests
		SET status = ?, approver_user_id = ?, decision_note = ?, decided_at = ?, expires_at = ?, updated_at = ?
		WHERE id = ? AND status = ?`),
		string(status), approverID, note, store.TimeArg(now), timeArg(expiresAt), store.TimeArg(now), id, string(StatusPending))
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, r.missOrState(ctx, id)
	}
	return r.Get(ctx, id)
}

// Revoke ends an approved grant early. It fails with ErrState unless the
// request is currently approved.
func (r *Repo) Revoke(ctx context.Context, id, note string) (*Request, error) {
	now := time.Now().UTC()
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE access_requests
		SET status = ?, decision_note = ?, updated_at = ? WHERE id = ? AND status = ?`),
		string(StatusRevoked), note, store.TimeArg(now), id, string(StatusApproved))
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, r.missOrState(ctx, id)
	}
	return r.Get(ctx, id)
}

// ExpireDue transitions approved grants whose window has passed to expired and
// returns how many changed. Used by the expiry sweeper (ADR 0018).
func (r *Repo) ExpireDue(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE access_requests
		SET status = ?, updated_at = ? WHERE status = ? AND expires_at <= ?`),
		string(StatusExpired), store.TimeArg(now), string(StatusApproved), store.TimeArg(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// missOrState distinguishes a missing request from one that was not in the
// expected state for the update.
func (r *Repo) missOrState(ctx context.Context, id string) error {
	if _, err := r.Get(ctx, id); errors.Is(err, ErrNotFound) {
		return ErrNotFound
	}
	return ErrState
}

func (r *Repo) query(ctx context.Context, where string, args ...any) ([]*Request, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT `+cols+` FROM access_requests `+where), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Request{}
	for rows.Next() {
		req, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, req)
	}
	return out, rows.Err()
}

type scanner interface{ Scan(dest ...any) error }

func scan(s scanner) (*Request, error) {
	var (
		req                                 Request
		status                              string
		policyID, targetID, asgID, approver sql.NullString
		decided, expires, created, updated  store.NullTime
	)
	err := s.Scan(&req.ID, &req.UserID, &policyID, &targetID, &asgID, &req.Protocol, &req.Reason, &req.RequestedMinutes,
		&status, &approver, &req.DecisionNote, &decided, &expires, &created, &updated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	req.PolicyID, req.TargetID, req.ASGID, req.ApproverUserID = policyID.String, targetID.String, asgID.String, approver.String
	req.Status = Status(status)
	req.DecidedAt, req.ExpiresAt = decided.Ptr(), expires.Ptr()
	req.CreatedAt, req.UpdatedAt = created.Time, updated.Time
	return &req, nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func timeArg(t *time.Time) any {
	if t == nil {
		return nil
	}
	return store.TimeArg(*t)
}
