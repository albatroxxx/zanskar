// SPDX-License-Identifier: Apache-2.0

// Package user holds the user model, roles and the repository over the users
// and user_roles tables. Authentication lives in package auth.
package user

import (
	"errors"
	"regexp"
	"time"
)

// Role is one of the three Zanskar roles (ADR 0006).
type Role string

// Roles.
const (
	RoleAdmin   Role = "admin"
	RoleAuditor Role = "auditor"
	RoleUser    Role = "user"
)

// ValidRole reports whether r is a known role.
func ValidRole(r Role) bool {
	return r == RoleAdmin || r == RoleAuditor || r == RoleUser
}

// Status of an account.
type Status string

// Statuses.
const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
	StatusLocked   Status = "locked"
)

// User is an account. PasswordHash is never serialised.
type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	Email        string     `json:"email,omitempty"`
	DisplayName  string     `json:"display_name"`
	Status       Status     `json:"status"`
	Roles        []Role     `json:"roles"`
	IdPID        string     `json:"idp_id,omitempty"`
	ExternalID   string     `json:"external_id,omitempty"`
	FailedLogins int        `json:"-"`
	LockedUntil  *time.Time `json:"locked_until,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	// MustChangePassword is set when an administrator set or generated the
	// password: the user replaces it at their next sign-in before anything
	// else (QA finding R25).
	MustChangePassword bool `json:"must_change_password"`

	PasswordHash string `json:"-"`
}

// HasRole reports whether the user holds r.
func (u *User) HasRole(r Role) bool {
	for _, have := range u.Roles {
		if have == r {
			return true
		}
	}
	return false
}

// CanConnect reports whether the account may see targets, request access and
// open sessions: it holds user or admin. An account holding only auditor is
// review-only (ADR 0006) and is refused even when a policy names it.
func (u *User) CanConnect() bool {
	return u.HasRole(RoleUser) || u.HasRole(RoleAdmin)
}

// Errors returned by the repository.
var (
	ErrNotFound      = errors.New("user: not found")
	ErrDuplicate     = errors.New("user: username or email already exists")
	ErrLastAdmin     = errors.New("user: cannot remove the last admin")
	ErrInvalidInput  = errors.New("user: invalid input")
	ErrInvalidRole   = errors.New("user: invalid role")
	ErrUsernameShape = errors.New("user: username must be 2-64 characters of letters, digits, '.', '_' or '-'")
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}$`)

// ValidUsername reports whether s is an acceptable username.
func ValidUsername(s string) bool { return usernameRe.MatchString(s) }
