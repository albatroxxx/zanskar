// SPDX-License-Identifier: Apache-2.0

// Package access implements just-in-time access approvals (PIM, ADR 0018): a
// user who is eligible for a target (through a policy with require_approval)
// holds no standing access to it, but may request access with a reason and a
// duration; an admin approves or denies, and an approved request becomes a
// time-bounded grant that expires on its own. The connect flow consults the
// grant (see ADR 0018); this package owns the request/grant lifecycle.
package access

import (
	"errors"
	"time"
)

// Status is the lifecycle state of an access request.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusExpired  Status = "expired"
	StatusRevoked  Status = "revoked"
)

// DefaultMaxGrantMinutes caps a grant when the eligible policy sets no
// max_session_minutes of its own.
const DefaultMaxGrantMinutes = 480 // 8 hours

// Request is an access request and, once approved, the time-bounded grant it
// becomes. Exactly one of TargetID and ASGID is set.
type Request struct {
	ID               string     `json:"id"`
	UserID           string     `json:"user_id"`
	PolicyID         string     `json:"policy_id,omitempty"`
	TargetID         string     `json:"target_id,omitempty"`
	ASGID            string     `json:"asg_id,omitempty"`
	Protocol         string     `json:"protocol"`
	Reason           string     `json:"reason"`
	RequestedMinutes int        `json:"requested_minutes"`
	Status           Status     `json:"status"`
	ApproverUserID   string     `json:"approver_user_id,omitempty"`
	DecisionNote     string     `json:"decision_note,omitempty"`
	DecidedAt        *time.Time `json:"decided_at,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// Active reports whether this is an approved grant still within its window.
func (r *Request) Active(now time.Time) bool {
	return r.Status == StatusApproved && r.ExpiresAt != nil && now.Before(*r.ExpiresAt)
}

// Errors.
var (
	ErrNotFound = errors.New("access: request not found")
	ErrInvalid  = errors.New("access: invalid input")
	ErrState    = errors.New("access: request is not in a state for this action")
)
