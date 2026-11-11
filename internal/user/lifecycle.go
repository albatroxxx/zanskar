// SPDX-License-Identifier: Apache-2.0

package user

import (
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/states"
)

// State is what holds of an account now (ADR 0047). Status is what an
// administrator set; State adds the lock that wrong passwords set, which
// lives in locked_until and showed nowhere (2026-11-09: a locked-out account
// read "Active" in the Users table).
type State string

// Account states.
const (
	StateActive    State = "active"
	StateLockedOut State = "locked_out"
	StateDisabled  State = "disabled"
	StateLocked    State = "locked"
)

// StateOf derives the account's state from its stored status and its lock.
func StateOf(status Status, lockedUntil *time.Time, now time.Time) State {
	switch status {
	case StatusDisabled:
		return StateDisabled
	case StatusLocked:
		return StateLocked
	}
	if lockedUntil != nil && now.Before(*lockedUntil) {
		return StateLockedOut
	}
	return StateActive
}

// Lifecycle is the account's declared lifecycle.
var Lifecycle = states.New("user", []string{string(StateActive), string(StateLockedOut), string(StateDisabled), string(StateLocked)},
	states.Move{From: "active", To: "locked_out", By: "five wrong passwords or codes"},
	states.Move{From: "locked_out", To: "active", By: "the lock lapses, a completed sign-in, or a password reset"},
	states.Move{From: "active", To: "disabled", By: audit.UserUpdate},
	states.Move{From: "active", To: "disabled", By: "the directory no longer lists the person (sync, SCIM)"},
	states.Move{From: "locked_out", To: "disabled", By: audit.UserUpdate},
	states.Move{From: "disabled", To: "active", By: audit.UserUpdate},
	states.Move{From: "disabled", To: "active", By: "the person is back in the directory"},
	states.Move{From: "active", To: "locked", By: audit.UserUpdate},
	states.Move{From: "locked", To: "active", By: audit.UserUpdate},
	states.Move{From: "disabled", To: "locked", By: audit.UserUpdate},
	states.Move{From: "locked", To: "disabled", By: audit.UserUpdate},
).Describe(states.Doc{
	Field:   "state",
	Schemas: []string{"User"},
	Derivation: "`disabled` and `locked` are the stored `status`; an `active` account with `locked_until` in the future is `locked_out`; " +
		"otherwise `active`. `directory_removed_at` beside `disabled` says the directory took the person away.",
	Notes: []string{
		"`locked` behaves exactly like `disabled` and only a raw PUT sets it; whether to retire it is an open question of ADR 0047.",
		"Setting `status: active` does not clear a lockout; a password reset or a completed sign-in does.",
		"Deleting an account removes its row (ADR 0046): deletion is not a state.",
	},
})
