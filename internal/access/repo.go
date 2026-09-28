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
	status, approver_user_id, decision_note, decided_at, expires_at, created_at, updated_at, extends_request_id`

// selectRequests reads a request with the names beside it. Every WHERE that
// follows it must qualify columns with r., since the joined tables share
// names such as status and created_at.
const selectRequests = `SELECT r.id, r.user_id, r.policy_id, r.target_id, r.asg_id, r.protocol, r.reason, r.requested_minutes,
	r.status, r.approver_user_id, r.decision_note, r.decided_at, r.expires_at, r.created_at, r.updated_at, r.extends_request_id,
	r.approved_minutes, u.username, a.username, t.name, g.name
	FROM access_requests r
	LEFT JOIN users u ON u.id = r.user_id
	LEFT JOIN users a ON a.id = r.approver_user_id
	LEFT JOIN targets t ON t.id = r.target_id
	LEFT JOIN autoscaling_groups g ON g.id = r.asg_id`

// Create inserts req as a pending request, setting ID, status and timestamps.
func (r *Repo) Create(ctx context.Context, req *Request) error {
	now := time.Now().UTC()
	req.ID = store.NewID()
	req.Status = StatusPending
	req.CreatedAt, req.UpdatedAt = now, now
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO access_requests (`+cols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		req.ID, req.UserID, nullStr(req.PolicyID), nullStr(req.TargetID), nullStr(req.ASGID), req.Protocol, req.Reason, req.RequestedMinutes,
		string(req.Status), nullStr(req.ApproverUserID), req.DecisionNote, timeArg(req.DecidedAt), timeArg(req.ExpiresAt), store.TimeArg(now), store.TimeArg(now),
		nullStr(req.ExtendsRequestID))
	return err
}

// Open returns the request that already occupies the (user, target or ASG,
// protocol) tuple: a pending request, or an approved grant still inside its
// window. One such request at a time is the rule (ADR 0018, amended); a
// second pending one would only give the approver the same decision twice.
// ErrNotFound when the tuple is free.
func (r *Repo) Open(ctx context.Context, userID, targetID, asgID, protocol string, now time.Time) (*Request, error) {
	list, err := r.query(ctx, `WHERE r.user_id = ? AND r.protocol = ? AND (r.target_id = ? OR r.asg_id = ?)
		AND (r.status = ? OR (r.status = ? AND r.expires_at > ?)) ORDER BY r.created_at DESC LIMIT 1`,
		userID, protocol, nullStr(targetID), nullStr(asgID), string(StatusPending), string(StatusApproved), store.TimeArg(now))
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, ErrNotFound
	}
	return list[0], nil
}

// Get returns one request by id.
func (r *Repo) Get(ctx context.Context, id string) (*Request, error) {
	row := r.db.QueryRowContext(ctx, r.db.Rebind(selectRequests+` WHERE r.id = ?`), id)
	return scan(row)
}

// ListByUser returns a user's own requests, newest first.
func (r *Repo) ListByUser(ctx context.Context, userID string) ([]*Request, error) {
	return r.query(ctx, `WHERE r.user_id = ? ORDER BY r.created_at DESC LIMIT 500`, userID)
}

// List returns requests for the admin queue, newest first; status "" means all.
func (r *Repo) List(ctx context.Context, status Status) ([]*Request, error) {
	if status == "" {
		return r.query(ctx, `ORDER BY r.created_at DESC LIMIT 500`)
	}
	return r.query(ctx, `WHERE r.status = ? ORDER BY r.created_at DESC LIMIT 500`, string(status))
}

// ActiveForUser returns a user's approved, unexpired grants.
func (r *Repo) ActiveForUser(ctx context.Context, userID string, now time.Time) ([]*Request, error) {
	return r.query(ctx, `WHERE r.user_id = ? AND r.status = ? AND r.expires_at > ? ORDER BY r.expires_at`,
		userID, string(StatusApproved), store.TimeArg(now))
}

// HasActiveGrant reports whether the user holds an approved, unexpired grant
// for the given target (or ASG) and protocol. The connect gate uses it to admit
// an approval-gated session (ADR 0018). Exactly one of targetID / asgID is set.
func (r *Repo) HasActiveGrant(ctx context.Context, userID, targetID, asgID, protocol string, now time.Time) (bool, error) {
	var one int
	err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT 1 FROM access_requests
		WHERE user_id = ? AND protocol = ? AND status = ? AND expires_at > ? AND (target_id = ? OR asg_id = ?) LIMIT 1`),
		userID, protocol, string(StatusApproved), store.TimeArg(now), nullStr(targetID), nullStr(asgID)).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Decide moves a pending request to approved or denied. expiresAt and the
// granted minutes are set on approval (nil and zero on denial). It fails with
// ErrState if the request is no longer pending, ErrNotFound if it does not
// exist.
func (r *Repo) Decide(ctx context.Context, id, approverID string, status Status, note string, expiresAt *time.Time, approvedMinutes int) (*Request, error) {
	now := time.Now().UTC()
	var minutes any
	if approvedMinutes > 0 {
		minutes = approvedMinutes
	}
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE access_requests
		SET status = ?, approver_user_id = ?, decision_note = ?, decided_at = ?, expires_at = ?, approved_minutes = ?, updated_at = ?
		WHERE id = ? AND status = ?`),
		string(status), approverID, note, store.TimeArg(now), timeArg(expiresAt), minutes, store.TimeArg(now), id, string(StatusPending))
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

// DueForExpiry returns approved grants whose window has passed (as of now), so
// the sweeper can audit each before flipping them with ExpireDue under the same
// cutoff.
func (r *Repo) DueForExpiry(ctx context.Context, now time.Time) ([]*Request, error) {
	return r.query(ctx, `WHERE r.status = ? AND r.expires_at <= ? ORDER BY r.expires_at`,
		string(StatusApproved), store.TimeArg(now))
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
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(selectRequests+` `+where), args...)
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
		extends, uname, aname, tname, gname sql.NullString
		approved                            sql.NullInt64
		decided, expires, created, updated  store.NullTime
	)
	err := s.Scan(&req.ID, &req.UserID, &policyID, &targetID, &asgID, &req.Protocol, &req.Reason, &req.RequestedMinutes,
		&status, &approver, &req.DecisionNote, &decided, &expires, &created, &updated, &extends, &approved, &uname, &aname, &tname, &gname)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	req.PolicyID, req.TargetID, req.ASGID, req.ApproverUserID = policyID.String, targetID.String, asgID.String, approver.String
	req.Username, req.ApproverUsername, req.TargetName, req.ASGName = uname.String, aname.String, tname.String, gname.String
	req.ExtendsRequestID, req.ApprovedMinutes = extends.String, int(approved.Int64)
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
