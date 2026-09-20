// SPDX-License-Identifier: Apache-2.0

// Package group holds groups and their membership. Access policies bind
// groups to targets; a user reaches a target only through a group.
package group

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// Group is a named set of users.
type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IdPID       string    `json:"idp_id,omitempty"`
	ExternalID  string    `json:"external_id,omitempty"`
	MemberCount int       `json:"member_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Member is a user in a group with the time they were added.
type Member struct {
	UserID      string    `json:"user_id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	AddedAt     time.Time `json:"added_at"`
}

// Errors.
var (
	ErrNotFound     = errors.New("group: not found")
	ErrDuplicate    = errors.New("group: name already exists")
	ErrInvalidInput = errors.New("group: invalid input")
	ErrSynced       = errors.New("group: membership is managed by an identity provider")
)

// Repo reads and writes groups.
type Repo struct {
	db *store.DB
}

// NewRepo returns a repository over db.
func NewRepo(db *store.DB) *Repo { return &Repo{db: db} }

const groupCols = `g.id, g.name, g.description, g.idp_id, g.external_id, g.created_at, g.updated_at,
	(SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id)`

func validName(name string) error {
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 64 {
		return fmt.Errorf("%w: name must be 1-64 characters", ErrInvalidInput)
	}
	return nil
}

// Create inserts g. ID and timestamps are set.
func (r *Repo) Create(ctx context.Context, g *Group) error {
	g.Name = strings.TrimSpace(g.Name)
	if err := validName(g.Name); err != nil {
		return err
	}
	now := time.Now().UTC()
	g.ID = store.NewID()
	g.CreatedAt, g.UpdatedAt = now, now
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO groups (id, name, description, idp_id, external_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`),
		g.ID, g.Name, g.Description, nullStr(g.IdPID), nullStr(g.ExternalID), store.TimeArg(now), store.TimeArg(now))
	if err != nil {
		if isUnique(err) {
			return ErrDuplicate
		}
		return err
	}
	return nil
}

// Get returns a group or ErrNotFound.
func (r *Repo) Get(ctx context.Context, id string) (*Group, error) {
	row := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT `+groupCols+` FROM groups g WHERE g.id = ?`), id)
	return scanGroup(row)
}

// List returns groups ordered by name, paginated by the last name seen.
func (r *Repo) List(ctx context.Context, afterName string, limit int) ([]*Group, string, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT `+groupCols+` FROM groups g
		WHERE LOWER(g.name) > LOWER(?) ORDER BY LOWER(g.name) LIMIT ?`), afterName, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []*Group{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].Name
	}
	return out, next, nil
}

// Update renames or re-describes a group.
func (r *Repo) Update(ctx context.Context, id, name, description string) error {
	name = strings.TrimSpace(name)
	if err := validName(name); err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE groups SET name = ?, description = ?, updated_at = ? WHERE id = ?`),
		name, description, store.TimeArg(time.Now()), id)
	if err != nil {
		if isUnique(err) {
			return ErrDuplicate
		}
		return err
	}
	return affected(res)
}

// Delete removes a group. Policies bound to it cascade away (schema).
func (r *Repo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM groups WHERE id = ?`), id)
	if err != nil {
		return err
	}
	return affected(res)
}

// Members lists the users in a group, ordered by username.
func (r *Repo) Members(ctx context.Context, groupID string) ([]Member, error) {
	if _, err := r.Get(ctx, groupID); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT u.id, u.username, u.display_name, gm.added_at
		FROM group_members gm JOIN users u ON u.id = gm.user_id WHERE gm.group_id = ? ORDER BY LOWER(u.username)`), groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Member{}
	for rows.Next() {
		var m Member
		var added store.NullTime
		if err := rows.Scan(&m.UserID, &m.Username, &m.DisplayName, &added); err != nil {
			return nil, err
		}
		m.AddedAt = added.Time
		out = append(out, m)
	}
	return out, rows.Err()
}

// MemberUsers returns the full user records of a group's members.
func (r *Repo) MemberUsers(ctx context.Context, groupID string) ([]*user.User, error) {
	members, err := r.Members(ctx, groupID)
	if err != nil {
		return nil, err
	}
	users := user.NewRepo(r.db)
	out := make([]*user.User, 0, len(members))
	for _, m := range members {
		u, err := users.GetByID(ctx, m.UserID)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

// SetMembers replaces the membership. It returns the ids added and removed
// so the caller can audit the change. Unknown user ids are rejected.
func (r *Repo) SetMembers(ctx context.Context, groupID string, userIDs []string) (added, removed []string, err error) {
	g, err := r.Get(ctx, groupID)
	if err != nil {
		return nil, nil, err
	}
	if g.IdPID != "" {
		return nil, nil, ErrSynced
	}
	want := map[string]bool{}
	for _, id := range userIDs {
		if id != "" {
			want[id] = true
		}
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	rows, err := tx.QueryContext(ctx, r.db.Rebind(`SELECT user_id FROM group_members WHERE group_id = ?`), groupID)
	if err != nil {
		return nil, nil, err
	}
	have := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close() //nolint:sqlclosecheck // explicit close: SQLite single connection, writes follow
			return nil, nil, err
		}
		have[id] = true
	}
	// Close explicitly (not deferred): SQLite runs on one connection and the
	// writes below would deadlock behind an open cursor.
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	added, removed = []string{}, []string{}
	now := store.TimeArg(time.Now())
	for id := range have {
		if !want[id] {
			if _, err := tx.ExecContext(ctx, r.db.Rebind(`DELETE FROM group_members WHERE group_id = ? AND user_id = ?`), groupID, id); err != nil {
				return nil, nil, err
			}
			removed = append(removed, id)
		}
	}
	for id := range want {
		if !have[id] {
			if _, err := tx.ExecContext(ctx, r.db.Rebind(`INSERT INTO group_members (group_id, user_id, added_at) VALUES (?, ?, ?)`), groupID, id, now); err != nil {
				if isFK(err) {
					return nil, nil, fmt.Errorf("%w: unknown user %s", ErrInvalidInput, id)
				}
				return nil, nil, err
			}
			added = append(added, id)
		}
	}
	if _, err := tx.ExecContext(ctx, r.db.Rebind(`UPDATE groups SET updated_at = ? WHERE id = ?`), now, groupID); err != nil {
		return nil, nil, err
	}
	return added, removed, tx.Commit()
}

// AddMember adds one user; adding an existing member is a no-op.
func (r *Repo) AddMember(ctx context.Context, groupID, userID string) error {
	g, err := r.Get(ctx, groupID)
	if err != nil {
		return err
	}
	if g.IdPID != "" {
		return ErrSynced
	}
	var n int
	if err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT COUNT(*) FROM group_members WHERE group_id = ? AND user_id = ?`), groupID, userID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err = r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO group_members (group_id, user_id, added_at) VALUES (?, ?, ?)`),
		groupID, userID, store.TimeArg(time.Now()))
	if err != nil && isFK(err) {
		return fmt.Errorf("%w: unknown user %s", ErrInvalidInput, userID)
	}
	return err
}

// RemoveMember removes one user; removing a non-member is a no-op.
func (r *Repo) RemoveMember(ctx context.Context, groupID, userID string) error {
	g, err := r.Get(ctx, groupID)
	if err != nil {
		return err
	}
	if g.IdPID != "" {
		return ErrSynced
	}
	_, err = r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM group_members WHERE group_id = ? AND user_id = ?`), groupID, userID)
	return err
}

// GroupsForUser returns every group the user belongs to, ordered by name.
func (r *Repo) GroupsForUser(ctx context.Context, userID string) ([]*Group, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT `+groupCols+` FROM groups g
		JOIN group_members gm ON gm.group_id = g.id WHERE gm.user_id = ? ORDER BY LOWER(g.name)`), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Group{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

type scanner interface{ Scan(dest ...any) error }

func scanGroup(s scanner) (*Group, error) {
	var (
		g                Group
		idp, ext         sql.NullString
		created, updated store.NullTime
	)
	if err := s.Scan(&g.ID, &g.Name, &g.Description, &idp, &ext, &created, &updated, &g.MemberCount); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	g.IdPID, g.ExternalID = idp.String, ext.String
	g.CreatedAt, g.UpdatedAt = created.Time, updated.Time
	return &g, nil
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

func isUnique(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate key")
}

func isFK(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "foreign key")
}
