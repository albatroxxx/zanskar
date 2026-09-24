// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
)

// Repo reads and writes access policies.
type Repo struct {
	db *store.DB
}

// NewRepo returns a repository over db.
func NewRepo(db *store.DB) *Repo { return &Repo{db: db} }

const cols = `id, name, description, enabled, group_id, user_id, target_selector, protocols, time_windows,
	max_session_minutes, idle_timeout_minutes, allow_clipboard, allow_file_transfer, require_mfa, require_approval,
	created_by, created_at, updated_at`

// Create validates and inserts p, setting ID and timestamps.
func (r *Repo) Create(ctx context.Context, p *Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC()
	p.ID, p.CreatedAt, p.UpdatedAt = store.NewID(), now, now
	sel, protos, wins, err := encode(p)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO access_policies (`+cols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		p.ID, p.Name, p.Description, p.Enabled, nullStr(p.GroupID), nullStr(p.UserID), sel, protos, wins,
		nullInt(p.MaxSessionMinutes), p.IdleTimeoutMinutes, p.AllowClipboard, p.AllowFileTransfer, p.RequireMFA, p.RequireApproval,
		nullStr(p.CreatedBy), store.TimeArg(now), store.TimeArg(now))
	if err != nil {
		return mapErr(err)
	}
	return nil
}

// Update replaces every editable field of the policy with the given id.
func (r *Repo) Update(ctx context.Context, p *Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	sel, protos, wins, err := encode(p)
	if err != nil {
		return err
	}
	p.UpdatedAt = time.Now().UTC()
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE access_policies SET name = ?, description = ?, enabled = ?, group_id = ?, user_id = ?,
		target_selector = ?, protocols = ?, time_windows = ?, max_session_minutes = ?, idle_timeout_minutes = ?,
		allow_clipboard = ?, allow_file_transfer = ?, require_mfa = ?, require_approval = ?, updated_at = ? WHERE id = ?`),
		p.Name, p.Description, p.Enabled, nullStr(p.GroupID), nullStr(p.UserID), sel, protos, wins, nullInt(p.MaxSessionMinutes), p.IdleTimeoutMinutes,
		p.AllowClipboard, p.AllowFileTransfer, p.RequireMFA, p.RequireApproval, store.TimeArg(p.UpdatedAt), p.ID)
	if err != nil {
		return mapErr(err)
	}
	return affected(res)
}

// Get returns one policy.
func (r *Repo) Get(ctx context.Context, id string) (*Policy, error) {
	row := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT `+cols+` FROM access_policies WHERE id = ?`), id)
	return scan(row)
}

// List returns policies ordered by name after the given name.
func (r *Repo) List(ctx context.Context, afterName string, limit int) ([]*Policy, string, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT `+cols+` FROM access_policies WHERE name > ? ORDER BY name LIMIT ?`), afterName, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()
	out, err := scanAll(rows)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].Name
	}
	return out, next, nil
}

// Delete removes a policy. Open sessions referencing it keep a NULL policy_id.
func (r *Repo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM access_policies WHERE id = ?`), id)
	if err != nil {
		return err
	}
	return affected(res)
}

// ForUser returns the enabled policies that apply to the user: those bound to
// the user directly and those bound to any group they belong to. This is the
// input to Evaluate.
func (r *Repo) ForUser(ctx context.Context, userID string) ([]*Policy, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT `+qualify(cols, "p")+` FROM access_policies p
		WHERE p.enabled = TRUE AND (p.user_id = ? OR p.group_id IN (SELECT group_id FROM group_members WHERE user_id = ?))
		ORDER BY p.name`), userID, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanAll(rows)
}

// ---- helpers

func encode(p *Policy) (sel, protos, wins []byte, err error) {
	if sel, err = json.Marshal(p.Selector); err != nil {
		return
	}
	if protos, err = json.Marshal(p.Protocols); err != nil {
		return
	}
	wins, err = json.Marshal(p.TimeWindows)
	return
}

type scanner interface{ Scan(dest ...any) error }

func scan(s scanner) (*Policy, error) {
	var (
		p                 Policy
		sel, protos, wins []byte
		maxSession        sql.NullInt64
		groupID, userID   sql.NullString
		createdBy         sql.NullString
		created, updated  store.NullTime
	)
	err := s.Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &groupID, &userID, &sel, &protos, &wins,
		&maxSession, &p.IdleTimeoutMinutes, &p.AllowClipboard, &p.AllowFileTransfer, &p.RequireMFA, &p.RequireApproval,
		&createdBy, &created, &updated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal(sel, &p.Selector); err != nil {
		return nil, fmt.Errorf("policy %s: bad selector: %w", p.ID, err)
	}
	if err := json.Unmarshal(protos, &p.Protocols); err != nil {
		return nil, fmt.Errorf("policy %s: bad protocols: %w", p.ID, err)
	}
	if err := json.Unmarshal(wins, &p.TimeWindows); err != nil {
		return nil, fmt.Errorf("policy %s: bad time windows: %w", p.ID, err)
	}
	if p.TimeWindows == nil {
		p.TimeWindows = []TimeWindow{}
	}
	if maxSession.Valid {
		v := int(maxSession.Int64)
		p.MaxSessionMinutes = &v
	}
	p.GroupID, p.UserID = groupID.String, userID.String
	p.CreatedBy = createdBy.String
	p.CreatedAt, p.UpdatedAt = created.Time, updated.Time
	return &p, nil
}

func scanAll(rows *sql.Rows) ([]*Policy, error) {
	out := []*Policy{}
	for rows.Next() {
		p, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func qualify(columns, alias string) string {
	parts := strings.Split(columns, ",")
	for i, c := range parts {
		parts[i] = alias + "." + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}

func nullInt(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func affected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func mapErr(err error) error {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate key") {
		return ErrDuplicate
	}
	if strings.Contains(msg, "foreign key") {
		return fmt.Errorf("%w: group or user does not exist", ErrInvalidInput)
	}
	if strings.Contains(msg, "check constraint") || strings.Contains(msg, "check failed") {
		return fmt.Errorf("%w: exactly one of group_id or user_id is required", ErrInvalidInput)
	}
	return err
}
