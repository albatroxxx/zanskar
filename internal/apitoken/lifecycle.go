// SPDX-License-Identifier: Apache-2.0

package apitoken

import (
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/states"
)

// State is what holds of a token now (ADR 0047).
type State string

// Token states.
const (
	StateActive  State = "active"
	StateExpired State = "expired"
	StateRevoked State = "revoked"
)

// StateOf derives a token's state from its expiry and revocation.
func StateOf(expiresAt time.Time, revokedAt *time.Time, now time.Time) State {
	switch {
	case revokedAt != nil:
		return StateRevoked
	case !now.Before(expiresAt):
		return StateExpired
	}
	return StateActive
}

// Lifecycle is the token's declared lifecycle (ADR 0044).
var Lifecycle = states.New("API token", []string{string(StateActive), string(StateExpired), string(StateRevoked)},
	states.Move{From: "active", To: "expired", By: "expires_at passes"},
	states.Move{From: "active", To: "revoked", By: audit.APITokenRevoke},
	states.Move{From: "expired", To: "revoked", By: audit.APITokenRevoke},
).Describe(states.Doc{
	Field:      "state",
	Schemas:    []string{"APIToken"},
	Derivation: "`revoked` when `revoked_at` is set, else `expired` when `expires_at` is at or before now, else `active`.",
	Notes: []string{
		"The owner's own state is not part of it: a token of a disabled, demoted or password-change-owing administrator reads `active` and is refused with 401 (ADR 0047, open question).",
		"Rows are never deleted; revoking twice keeps the first time.",
	},
})
