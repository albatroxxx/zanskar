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
	failed_logins, locked_until, created_at, updated_at, last_login_at, must_change_password`

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
		(id, username, email, display_name, password_hash, status, idp_id, external_id, failed_logins, created_at, updated_at, must_change_password)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`),
		u.ID, u.Username, nullStr(u.Email), u.DisplayName, nullStr(u.PasswordHash), string(u.Status),
		nullStr(u.IdPID), nullStr(u.ExternalID), store.TimeArg(now), store.TimeArg(now), u.MustResetOnLogin)
	if err != nil {
		if store.IsUniqueViolation(err) {
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
	defer func() { _ = rows.Close() }()
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
		if store.IsUniqueViolation(err) {
			return ErrDuplicate
		}
		return err
	}
	return store.Affected(res, ErrNotFound)
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
// SetPasswordHash replaces the password; mustChange says whether the user
// has to replace it again at their next sign-in (an administrator's choice
// of password) or not (their own).
func (r *Repo) SetPasswordHash(ctx context.Context, id, hash string, mustChange bool) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE users SET password_hash = ?, must_change_password = ?, failed_logins = 0, locked_until = NULL, updated_at = ? WHERE id = ?`),
		hash, mustChange, store.TimeArg(time.Now()), id)
	if err != nil {
		return err
	}
	return store.Affected(res, ErrNotFound)
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
		// Sessions and recording views keep the account (ON DELETE RESTRICT);
		// a history that appeared after HasHistory was asked lands here.
		if store.IsForeignKeyViolation(err) {
			return ErrHasHistory
		}
		return err
	}
	return store.Affected(res, ErrNotFound)
}

// HasHistory reports whether sessions or recording views name the account,
// which keeps it from being deleted (the record keeps it; ADR 0019's reason).
func (r *Repo) HasHistory(ctx context.Context, id string) (bool, error) {
	var n int
	err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT (SELECT COUNT(*) FROM access_sessions WHERE user_id = ?)
		+ (SELECT COUNT(*) FROM recording_views WHERE user_id = ?)`), id, id).Scan(&n)
	return n > 0, err
}

// RecordLoginFailure counts a wrong password or a wrong second-factor code
// against the account (they share one count) and locks the account for
// lockFor once maxFailures is reached. It returns true when this failure
// locked the account.
func (r *Repo) RecordLoginFailure(ctx context.Context, id string, maxFailures int, lockFor time.Duration) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck
	// Increment in place, then read: the update holds the row until commit,
	// so failures recorded at the same moment each count. Reading first and
	// writing the sum back let two of them write the same number.
	res, err := tx.ExecContext(ctx, r.db.Rebind(`UPDATE users SET failed_logins = failed_logins + 1 WHERE id = ?`), id)
	if err != nil {
		return false, err
	}
	if err := store.Affected(res, ErrNotFound); err != nil {
		return false, err
	}
	var failed int
	if err := tx.QueryRowContext(ctx, r.db.Rebind(`SELECT failed_logins FROM users WHERE id = ?`), id).Scan(&failed); err != nil {
		return false, err
	}
	if failed < maxFailures {
		return false, tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, r.db.Rebind(`UPDATE users SET failed_logins = 0, locked_until = ? WHERE id = ?`),
		store.TimeArg(time.Now().Add(lockFor)), id); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// RecordLoginSuccess clears the failure counter and stamps last_login_at.
// Call it when a sign-in completes, not at a first factor that still owes a
// second: the count is the budget for guessing either one.
func (r *Repo) RecordLoginSuccess(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = ? WHERE id = ?`),
		store.TimeArg(time.Now()), id)
	return err
}

// IsLocked reports whether the account may not sign in now: it is blocked,
// or wrong passwords have locked it until LockedUntil. Sign-in paths use it.
func (u *User) IsLocked(now time.Time) bool {
	if u.IsBlocked() {
		return true
	}
	return u.LockedUntil != nil && now.Before(*u.LockedUntil)
}

// IsBlocked reports whether an administrator has disabled or locked the
// account. It ignores the temporary lock that wrong passwords set: that one
// refuses new sign-ins only. Anyone who knows a username can set it, so if
// it also ended the sessions already signed in, anyone could sign the
// account's owner out (M6). Session checks use this.
func (u *User) IsBlocked() bool {
	return u.Status == StatusLocked || u.Status == StatusDisabled
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
	defer func() { _ = rows.Close() }()
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

func scanUser(s store.Scanner) (*User, error) {
	var (
		u                                   User
		email, hash, idp, ext               sql.NullString
		status                              string
		lockedUntil, created, updated, last store.NullTime
	)
	err := s.Scan(&u.ID, &u.Username, &email, &u.DisplayName, &hash, &status, &idp, &ext,
		&u.FailedLogins, &lockedUntil, &created, &updated, &last, &u.MustResetOnLogin)
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

// LinkExternal ties the account to an identity provider's subject, so that
// sign-ins through idpID find it by externalID (GetByExternalID). It writes
// the link and nothing else: roles, password, profile and status stay as they
// are. Whether an account may be linked at all is the caller's decision
// (idp.Provisioner.Resolve links only one with no password and no provider).
// ErrNotFound when there is no such account, ErrDuplicate when another
// account is already linked to that subject.
func (r *Repo) LinkExternal(ctx context.Context, id, idpID, externalID string) error {
	// The conditions the caller checked are repeated in the UPDATE, so two
	// first sign-ins asserting the same username at the same moment cannot
	// both link it: the second finds the row taken (S1 L4).
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE users SET idp_id = ?, external_id = ?, updated_at = ?
		WHERE id = ? AND (idp_id IS NULL OR idp_id = '') AND (password_hash IS NULL OR password_hash = '')`),
		idpID, externalID, store.TimeArg(time.Now()), id)
	if err != nil {
		if store.IsUniqueViolation(err) {
			return ErrDuplicate
		}
		return err
	}
	if err := store.Affected(res, ErrNotFound); err != nil {
		if _, gerr := r.GetByID(ctx, id); gerr == nil {
			// The account exists but is linked or has a password by now.
			return ErrDuplicate
		}
		return err
	}
	return nil
}

// GetByExternalID finds a user provisioned from an identity provider.
func (r *Repo) GetByExternalID(ctx context.Context, idpID, externalID string) (*User, error) {
	row := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT `+userCols+` FROM users WHERE idp_id = ? AND external_id = ?`), idpID, externalID)
	u, err := scanUser(row)
	if err != nil {
		return nil, err
	}
	u.Roles, err = r.roles(ctx, u.ID)
	return u, err
}
