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
	failed_logins, locked_until, created_at, updated_at, last_login_at, must_change_password, directory_removed_at,
	scim_external_id, scim_deleted_at`

// Create inserts u with the given roles. u.ID, CreatedAt and UpdatedAt are set.
// PasswordHash may be empty for externally authenticated users.
func (r *Repo) Create(ctx context.Context, u *User) error {
	return r.CreateInGroups(ctx, u, nil)
}

// CreateInGroups is Create that also makes the user a member of groupIDs, in
// the same transaction (2026-10-30: adding a user and then their groups was
// two pages): a group that does not exist, or whose members come from an
// identity provider, refuses the whole request with ErrUnknownGroup, so no
// half-made account is left behind.
func (r *Repo) CreateInGroups(ctx context.Context, u *User, groupIDs []string) error {
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

	groups := distinct(groupIDs)
	// One row at a time (QueryRow closes its cursor), before any write:
	// SQLite runs on one connection.
	for _, gid := range groups {
		var idp sql.NullString
		err := tx.QueryRowContext(ctx, r.db.Rebind(`SELECT idp_id FROM groups WHERE id = ?`), gid).Scan(&idp)
		if errors.Is(err, sql.ErrNoRows) || err == nil && idp.Valid && idp.String != "" {
			return fmt.Errorf("%w: %s", ErrUnknownGroup, gid)
		}
		if err != nil {
			return err
		}
	}

	_, err = tx.ExecContext(ctx, r.db.Rebind(`INSERT INTO users
		(id, username, email, display_name, password_hash, status, idp_id, external_id, failed_logins, created_at, updated_at, must_change_password, scim_external_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`),
		u.ID, u.Username, nullStr(u.Email), u.DisplayName, nullStr(u.PasswordHash), string(u.Status),
		nullStr(u.IdPID), nullStr(u.ExternalID), store.TimeArg(now), store.TimeArg(now), u.MustResetOnLogin, nullStr(u.SCIMExternalID))
	if err != nil {
		if store.IsUniqueViolation(err) {
			return ErrDuplicate
		}
		return err
	}
	if err := setRolesTx(ctx, tx, r.db, u.ID, u.Roles); err != nil {
		return err
	}
	for _, gid := range groups {
		if _, err := tx.ExecContext(ctx, r.db.Rebind(`INSERT INTO group_members (group_id, user_id, added_at) VALUES (?, ?, ?)`), gid, u.ID, store.TimeArg(now)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// distinct drops empty and repeated ids, keeping the first order.
func distinct(ids []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
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

// Update changes display name, email and status. A change of status is an
// administrator's decision and takes the account over from the directory
// sync: the mark that the sync disabled it goes, so the sync no longer
// enables it again (ADR 0035). Writing the status it already has keeps it.
func (r *Repo) Update(ctx context.Context, id, displayName, email string, status Status) error {
	if strings.TrimSpace(displayName) == "" {
		return fmt.Errorf("%w: display name required", ErrInvalidInput)
	}
	switch status {
	case StatusActive, StatusDisabled, StatusLocked:
	default:
		return fmt.Errorf("%w: bad status", ErrInvalidInput)
	}
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE users SET display_name = ?, email = ?, status = ?, updated_at = ?,
		directory_removed_at = CASE WHEN status <> ? THEN NULL ELSE directory_removed_at END WHERE id = ?`),
		displayName, nullStr(strings.ToLower(strings.TrimSpace(email))), string(status), store.TimeArg(time.Now()), string(status), id)
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
		removed, scimDeleted                store.NullTime
		scimExt                             sql.NullString
	)
	err := s.Scan(&u.ID, &u.Username, &email, &u.DisplayName, &hash, &status, &idp, &ext,
		&u.FailedLogins, &lockedUntil, &created, &updated, &last, &u.MustResetOnLogin, &removed, &scimExt, &scimDeleted)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.Email, u.PasswordHash, u.IdPID, u.ExternalID = email.String, hash.String, idp.String, ext.String
	u.Status = Status(status)
	u.LockedUntil, u.CreatedAt, u.UpdatedAt, u.LastLoginAt = lockedUntil.Ptr(), created.Time, updated.Time, last.Ptr()
	u.DirectoryRemovedAt, u.SCIMExternalID, u.SCIMDeletedAt = removed.Ptr(), scimExt.String, scimDeleted.Ptr()
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
	// An account the same provider provisioned (SCIM, or a listing) and
	// nobody has signed in to yet is linked here too: its subject is not
	// known until that first sign-in.
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE users SET idp_id = ?, external_id = ?, updated_at = ?
		WHERE id = ? AND (password_hash IS NULL OR password_hash = '')
		AND (idp_id IS NULL OR idp_id = '' OR (idp_id = ? AND (external_id IS NULL OR external_id = '')))`),
		idpID, externalID, store.TimeArg(time.Now()), id, idpID)
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

// ListByIdP returns every account linked to an identity provider, with its
// roles, read in full before it returns (one connection on SQLite).
func (r *Repo) ListByIdP(ctx context.Context, idpID string) ([]*User, error) {
	out, err := r.scanAll(ctx, `SELECT `+userCols+` FROM users WHERE idp_id = ? ORDER BY id`, idpID)
	if err != nil {
		return nil, err
	}
	for _, u := range out {
		if u.Roles, err = r.roles(ctx, u.ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// scanAll reads every row of a users query and closes the cursor before it
// returns, so the caller may query again (one connection on SQLite).
func (r *Repo) scanAll(ctx context.Context, query string, args ...any) ([]*User, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// DisableRemoved disables an active account because the person has left
// the directory, and marks it so (ADR 0035). It reports false when the
// account was not active: an administrator's decision stands.
func (r *Repo) DisableRemoved(ctx context.Context, id string, at time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE users SET status = 'disabled', directory_removed_at = ?, updated_at = ? WHERE id = ? AND status = 'active'`),
		store.TimeArg(at), store.TimeArg(at), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// EnableReturned enables an account the directory sync disabled, now the
// person is back in the directory. It reports false for any other account,
// so one an administrator disabled stays disabled.
func (r *Repo) EnableReturned(ctx context.Context, id string) (bool, error) {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE users SET status = 'active', directory_removed_at = NULL, updated_at = ?
		WHERE id = ? AND status = 'disabled' AND directory_removed_at IS NOT NULL`), store.TimeArg(time.Now()), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// Provision links an account an administrator created with no password to
// an identity provider that pushes its people (SCIM), before anyone has
// signed in: the provider, and its own id for the person, but no subject
// yet (LinkExternal binds it at the first sign-in). The conditions are
// repeated in the UPDATE, as LinkExternal does. ErrDuplicate when the
// account has a password or a provider by now.
func (r *Repo) Provision(ctx context.Context, id, idpID, scimExternalID string) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE users SET idp_id = ?, scim_external_id = ?, updated_at = ?
		WHERE id = ? AND (idp_id IS NULL OR idp_id = '') AND (password_hash IS NULL OR password_hash = '')`),
		idpID, nullStr(scimExternalID), store.TimeArg(time.Now()), id)
	if err != nil {
		return err
	}
	if err := store.Affected(res, ErrNotFound); err != nil {
		if _, gerr := r.GetByID(ctx, id); gerr == nil {
			return ErrDuplicate
		}
		return err
	}
	return nil
}

// SetSCIM records the provider's own id for the person and whether its
// SCIM client has deleted the account (deleted nil clears it).
func (r *Repo) SetSCIM(ctx context.Context, id, scimExternalID string, deleted *time.Time) error {
	var at any
	if deleted != nil {
		at = store.TimeArg(*deleted)
	}
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE users SET scim_external_id = ?, scim_deleted_at = ?, updated_at = ? WHERE id = ?`),
		nullStr(scimExternalID), at, store.TimeArg(time.Now()), id)
	if err != nil {
		return err
	}
	return store.Affected(res, ErrNotFound)
}

// Rename changes an account's username, as a provider renames a person
// (an Entra ID UPN change). ErrDuplicate when another account holds it.
func (r *Repo) Rename(ctx context.Context, id, username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if !ValidUsername(username) {
		return ErrUsernameShape
	}
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE users SET username = ?, updated_at = ? WHERE id = ?`), username, store.TimeArg(time.Now()), id)
	if err != nil {
		if store.IsUniqueViolation(err) {
			return ErrDuplicate
		}
		return err
	}
	return store.Affected(res, ErrNotFound)
}

// SCIMFilter narrows ListProvisioned to one attribute's value: "userName"
// (any case), "externalId" or "id"; empty Attr lists everyone.
type SCIMFilter struct{ Attr, Value string }

// ListProvisioned returns a page of the accounts linked to an identity
// provider that its SCIM client has not deleted, ordered by username, and
// how many there are in all. offset counts from 0.
func (r *Repo) ListProvisioned(ctx context.Context, idpID string, f SCIMFilter, offset, limit int) ([]*User, int, error) {
	where, args := `idp_id = ? AND scim_deleted_at IS NULL`, []any{idpID}
	switch f.Attr {
	case "":
	case "userName":
		where, args = where+` AND LOWER(username) = LOWER(?)`, append(args, f.Value)
	case "externalId":
		where, args = where+` AND scim_external_id = ?`, append(args, f.Value)
	case "id":
		where, args = where+` AND id = ?`, append(args, f.Value)
	default:
		return nil, 0, fmt.Errorf("%w: cannot filter on %q", ErrInvalidInput, f.Attr)
	}
	var total int
	if err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT COUNT(*) FROM users WHERE `+where), args...).Scan(&total); err != nil { // #nosec G202 -- where is built from constants; values are bound
		return nil, 0, err
	}
	out, err := r.scanAll(ctx, `SELECT `+userCols+` FROM users WHERE `+where+` ORDER BY LOWER(username) LIMIT ? OFFSET ?`, append(args, limit, offset)...) // #nosec G202 -- as above
	if err != nil {
		return nil, 0, err
	}
	for _, u := range out {
		if u.Roles, err = r.roles(ctx, u.ID); err != nil {
			return nil, 0, err
		}
	}
	return out, total, nil
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
