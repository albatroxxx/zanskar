// SPDX-License-Identifier: Apache-2.0

package access

import (
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/states"
)

// StateOf derives a request's state (ADR 0047): the stored status, except
// that an approval whose window has passed reads expired before the sweeper
// writes it (2026-11-09: the admin's Active grants listed such a grant, with
// a Revoke button, for up to a minute).
func StateOf(status Status, expiresAt *time.Time, now time.Time) Status {
	if status == StatusApproved && expiresAt != nil && !now.Before(*expiresAt) {
		return StatusExpired
	}
	return status
}

// Lifecycle is the request's declared lifecycle (ADR 0018).
var Lifecycle = states.New("access request",
	[]string{string(StatusPending), string(StatusApproved), string(StatusDenied), string(StatusExpired), string(StatusRevoked)},
	states.Move{From: "pending", To: "approved", By: audit.AccessRequestApprove},
	states.Move{From: "pending", To: "denied", By: audit.AccessRequestDeny},
	states.Move{From: "pending", To: "revoked", By: "the target or group is deleted (" + audit.TargetDelete + ")"},
	states.Move{From: "approved", To: "revoked", By: audit.AccessRequestRevoke},
	states.Move{From: "approved", To: "revoked", By: "the target or group is deleted (" + audit.TargetDelete + ")"},
	states.Move{From: "approved", To: "expired", By: audit.AccessGrantExpire},
).Describe(states.Doc{
	Field:   "state",
	Schemas: []string{"AccessRequest"},
	Derivation: "The stored `status`, except that `approved` with `expires_at` at or before now reads `expired`: the sweeper writes " +
		"`expired` once a minute, and the clock is the truth in between. A grant is active while `state` is `approved`.",
	Notes: []string{
		"Revoke applies to an active grant only; a lapsed one answers 409 with the state named.",
		"A pending request never expires on its own and cannot be withdrawn by the requester.",
	},
})
