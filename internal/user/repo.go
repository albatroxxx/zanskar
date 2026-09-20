// SPDX-License-Identifier: Apache-2.0

package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
)

// Repo reads and writes users.
type Repo struct {
	db *store.DB
}

// NewRepo returns a repository over db.
func NewRepo(db *store.DB) *Repo { return &Repo{db: db} }

const userCols = `id, username, email, display_name, password_hash, status, idp_id, external_id,
	failed_logins, locked_until, created_at, updated_at, last_login_at`

// Create inserts u with the given roles. u.ID, CreatedAt and UpdatedAt are set.
// PasswordHash may be empty for externally authenticated users.
func (r *Repo) Create(ctx context.Context, u *User) error {
	if !ValidUsername(u.Username) {
		return ErrUsernameShape
	}
	if strings.TrimSpace(u.DisplayName) == "" {
		return fmt.Errorf("%w: display name required", ErrInvalidInput)
	}
	for _, role := range u.Roles {
		if !ValidRole(role) {
			return ErrInvalidRole
		}
	}
	if u.Status == "" {
		u.Status = StatusActive
	}
	// Usernames and emails are stored lowercase; migration 0002 enforces
	// case-insensitive uniqueness at the database as well.
	u.Username = strings.ToLower(u.Username)
	u.Email = strings.ToLower(strings.TrimSpace(u.Email))
	now := time.Now().UTC()
	u.ID = store.NewID()
	u.CreatedAt, u.UpdatedAt = now, now

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	_, err = tx.ExecContext(ctx, r.db.Rebind(`INSERT INTO users
		(id, username, email, display_name, password_hash, status, idp_id, external_id, failed_logins, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`),
		u.ID, u.Username, nullStr(u.Email), u.DisplayName, nullStr(u.PasswordHash), string(u.Status),
		nullStr(u.IdPID), nullStr(u.ExternalID), store.TimeArg(now), store.TimeArg(now))
	if err != nil {
		if isUnique(err) {
			return ErrDuplicate
		}
		return err
	}
	if err := setRolesTx(ctx, tx, r.db, u.ID, u.Roles); err != nil {
		return err
	}
	return tx.Commit()
}

// GetByID returns the user or ErrNotFound.
func (r *Repo) GetByID(ctx context.Context, id string) (*User, error) {
	return r.getWhere(ctx, "id = ?", id)
}

// GetByUsername is case-insensitive on the username.
func (r *Repo) GetByUsername(ctx context.Context, username string) (*User, error) {
	return r.getWhere(ctx, "LOWER(username) = LOWER(?)", username)
}

func (r *Repo) getWhere(ctx context.Context, where string, arg any) (*User, error) {
	row := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT `+userCols+` FROM users WHERE `+where), arg)
	u, err := scanUser(row)
	if err != nil {
		return nil, err
	}
	u.Roles, err = r.roles(ctx, u.ID)
	return u, err
}

// List returns users ordered by username, paginated by the last username seen.
func (r *Repo) List(ctx context.Context, afterUsername string, limit int) ([]*User, string, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT `+userCols+` FROM users
		WHERE LOWER(username) > LOWER(?) ORDER BY LOWER(username) LIMIT ?`), afterUsername, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].Username
	}
	for _, u := range out {
		if u.Roles, err = r.roles(ctx, u.ID); err != nil {
			return nil, "", err
		}
	}
	return out, next, nil
}

// Update changes display name, email and status.
func (r *Repo) Update(ctx context.Context, id, displayName, email string, status Status) error {
	if strings.TrimSpace(displayName) == "" {
		return fmt.Errorf("%w: display name required", ErrInvalidInput)
	}
	switch status {
	case StatusActive, StatusDisabled, StatusLocked:
	default:
		return fmt.Errorf("%w: bad status", ErrInvalidInput)
	}
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE users SET display_name = ?, email = ?, status = ?, updated_at = ? WHERE id = ?`),
		displayName, nullStr(strings.ToLower(strings.TrimSpace(email))), string(status), store.TimeArg(time.Now()), id)
	if err != nil {
		if isUnique(err) {
			return ErrDuplicate
		}
		return err
	}
	return affected(res)
}

// SetRoles replaces the user's roles. It refuses to leave the system with no admin.
func (r *Repo) SetRoles(ctx context.Context, id string, roles []Role) error {
	for _, role := range roles {
		if !ValidRole(role) {
			return ErrInvalidRole
		}
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	keepsAdmin := false
	for _, role := range roles {
		if role == RoleAdmin {
			keepsAdmin = true
		}
	}
	if !keepsAdmin {
		var others int
		err := tx.QueryRowContext(ctx, r.db.Rebind(`SELECT COUNT(*) FROM user_roles ur JOIN users u ON u.id = ur.user_id
			WHERE ur.role = 'admin' AND ur.user_id <> ? AND u.status = 'active'`), id).Scan(&others)
		if err != nil {
			return err
		}
		if others == 0 {
			var isAdmin int
			if err := tx.QueryRowContext(ctx, r.db.Rebind(`SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role = 'admin'`), id).Scan(&isAdmin); err != nil {
				return err
			}
			if isAdmin > 0 {
				return ErrLastAdmin
			}
		}
	}
	if err := setRolesTx(ctx, tx, r.db, id, roles); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, r.db.Rebind(`UPDATE users SET updated_at = ? WHERE id = ?`), store.TimeArg(time.Now()), id); err != nil {
		return err
	}
	return tx.Commit()
}

// SetPasswordHash stores a new hash and clears lockout counters.
func (r *Repo) SetPasswordHash(ctx context.Context, id, hash string) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE users SET password_hash = ?, failed_logins = 0, locked_until = NULL, updated_at = ? WHERE id = ?`),
		hash, store.TimeArg(time.Now()), id)
	if err != nil {
		return err
	}
	return affected(res)
}

// Delete removes the user. Audit rows keep the id as plain text by design.
func (r *Repo) Delete(ctx context.Context, id string) error {
	u, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if u.HasRole(RoleAdmin) {
		var others int
		if err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT COUNT(*) FROM user_roles ur JOIN users u ON u.id = ur.user_id
			WHERE ur.role = 'admin' AND ur.user_id <> ? AND u.status = 'active'`), id).Scan(&others); err != nil {
			return err
		}
		if others == 0 {
			return ErrLastAdmin
		}
	}
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM users WHERE id = ?`), id)
	if err != nil {
		return err
	}
	return affected(res)
}

// RecordLoginFailure increments the failure counter and locks the account
// for lockFor once maxFailures is reached. It returns true when the account
// is now locked.
func (r *Repo) RecordLoginFailure(ctx context.Context, id string, maxFailures int, lockFor time.Duration) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck
	var failed int
	if err := tx.QueryRowContext(ctx, r.db.Rebind(`SELECT failed_logins FROM users WHERE id = ?`), id).Scan(&failed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, err
	}
	failed++
	locked := failed >= maxFailures
	var lockedUntil any
	if locked {
		lockedUntil = store.TimeArg(time.Now().Add(lockFor))
		failed = 0
	}
	if _, err := tx.ExecContext(ctx, r.db.Rebind(`UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?`), failed, lockedUntil, id); err != nil {
		return false, err
	}
	return locked, tx.Commit()
}

// RecordLoginSuccess clears the failure counter and stamps last_login_at.
func (r *Repo) RecordLoginSuccess(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = ? WHERE id = ?`),
		store.TimeArg(time.Now()), id)
	return err
}

// IsLocked reports whether the account is currently locked out.
func (u *User) IsLocked(now time.Time) bool {
	if u.Status == StatusLocked || u.Status == StatusDisabled {
		return true
	}
	return u.LockedUntil != nil && now.Before(*u.LockedUntil)
}

// CountAdmins returns the number of active users holding admin.
func (r *Repo) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_roles ur JOIN users u ON u.id = ur.user_id WHERE ur.role = 'admin' AND u.status = 'active'`).Scan(&n)
	return n, err
}

func (r *Repo) roles(ctx context.Context, id string) ([]Role, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT role FROM user_roles WHERE user_id = ? ORDER BY role`), id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roles := []Role{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		roles = append(roles, Role(s))
	}
	return roles, rows.Err()
}

func setRolesTx(ctx context.Context, tx *sql.Tx, db *store.DB, id string, roles []Role) error {
	if _, err := tx.ExecContext(ctx, db.Rebind(`DELETE FROM user_roles WHERE user_id = ?`), id); err != nil {
		return err
	}
	seen := map[Role]bool{}
	for _, role := range roles {
		if seen[role] {
			continue
		}
		seen[role] = true
		if _, err := tx.ExecContext(ctx, db.Rebind(`INSERT INTO user_roles (user_id, role) VALUES (?, ?)`), id, string(role)); err != nil {
			return err
		}
	}
	return nil
}

type scanner interface{ Scan(dest ...any) error }

func scanUser(s scanner) (*User, error) {
	var (
		u                                   User
		email, hash, idp, ext               sql.NullString
		status                              string
		lockedUntil, created, updated, last store.NullTime
	)
	err := s.Scan(&u.ID, &u.Username, &email, &u.DisplayName, &hash, &status, &idp, &ext,
		&u.FailedLogins, &lockedUntil, &created, &updated, &last)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.Email, u.PasswordHash, u.IdPID, u.ExternalID = email.String, hash.String, idp.String, ext.String
	u.Status = Status(status)
	u.LockedUntil, u.CreatedAt, u.UpdatedAt, u.LastLoginAt = lockedUntil.Ptr(), created.Time, updated.Time, last.Ptr()
	return &u, nil
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
