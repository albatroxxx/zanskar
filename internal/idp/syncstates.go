// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/states"
)

// SyncLifecycle is a listing provider's directory sync (ADR 0035, ADR 0047):
// where its last run stands. In process memory only.
var SyncLifecycle = states.New("directory sync",
	[]string{"not run", "running", "ok", "held", "failed"},
	states.Move{From: "not run", To: "running", By: "the first tick after start, or a manual run"},
	states.Move{From: "ok", To: "running", By: "the interval passes, or a manual run"},
	states.Move{From: "held", To: "running", By: "the interval passes, or a manual run (with apply_removals to force)"},
	states.Move{From: "failed", To: "running", By: "the interval passes, or a manual run"},
	states.Move{From: "running", To: "ok", By: audit.IdPSync + " when something changed, or on a manual run"},
	states.Move{From: "running", To: "held", By: "removals held back: the listing was empty, or more than half the active accounts would go"},
	states.Move{From: "running", To: "failed", By: audit.IdPSync + " (failure) on a new or changed error; notified as provider_failing"},
).Describe(states.Doc{
	Derivation: "`IdentityProvider.sync`: `running`, `last{ok, error, held}` and `next_at`; absent for a provider that does not list (SCIM, sign-in only). The dashboard counts `failing`, `not_run` and `held_back`.",
	Notes: []string{
		"After a restart every provider reads `not run` until its first tick, so a failing provider's banner disappears and its next failure is announced again.",
		"\"Not answering\" on the sign-in page is the discovery probe, a different check from the sync.",
	},
})
