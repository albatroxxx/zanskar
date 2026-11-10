// SPDX-License-Identifier: Apache-2.0

package credential

import (
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/states"
)

// RotationState is where a certificate authority's two-phase key rotation
// stands (ADR 0022, ADR 0047): no rotation, a next key prepared, or cut over
// with the old key still to be removed from targets.
type RotationState string

// Rotation states.
const (
	RotationNone     RotationState = "none"
	RotationPrepared RotationState = "prepared"
	RotationCutOver  RotationState = "cut_over"
)

// RotationStateOf derives the rotation's state from the prepared and retired keys.
func RotationStateOf(r *Rotation) RotationState {
	switch {
	case r == nil:
		return RotationNone
	case r.PendingPublicKey != "":
		return RotationPrepared
	case r.RetiredPublicKey != "":
		return RotationCutOver
	}
	return RotationNone
}

// RotationLifecycle is the rotation's declared lifecycle.
var RotationLifecycle = states.New("authority rotation", []string{string(RotationNone), string(RotationPrepared), string(RotationCutOver)},
	states.Move{From: "none", To: "prepared", By: audit.CredentialRotatePrepare},
	states.Move{From: "prepared", To: "none", By: audit.CredentialRotateCancel},
	states.Move{From: "prepared", To: "cut_over", By: audit.CredentialRotate + " (cut over)"},
	states.Move{From: "cut_over", To: "none", By: audit.CredentialRotateRetire},
).Describe(states.Doc{
	Field:   "rotation_state",
	Schemas: []string{"Credential"},
	Derivation: "`prepared` while `rotation.pending_public_key` is set, else `cut_over` while `rotation.retired_public_key` is set, else `none`. " +
		"`ssh_ca` credentials only; absent on the others.",
	Notes: []string{
		"One rotation at a time: preparing a next key is refused while a retired key waits to be confirmed removed (2026-11-09: the next cut-over overwrote the reminder).",
		"A row from before that rule may hold both keys; it reads `prepared`, and the console still shows both reminders.",
	},
})
