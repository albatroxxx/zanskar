// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/states"
)

// FlowLifecycle is the connect flow's declared lifecycle (ADR 0047): the
// phases a session passes through between the Connect button and its row
// being closed. Nothing stores them; they live in the ticket store, the
// starting set, the registry and the run itself, and docs/lifecycles.md
// is where a reader finds them written down.
var FlowLifecycle = states.New("connect flow",
	[]string{"requested", "ticket issued", "redeemed", "starting", "live", "ending", "closing", "gone"},
	states.Move{From: "requested", To: "ticket issued", By: audit.SessionConnect + " (policy gate, pins, credentials, pre-flight)"},
	states.Move{From: "ticket issued", To: "redeemed", By: "the browser opens the WebSocket with the ticket (30 s, once, same browser)"},
	states.Move{From: "redeemed", To: "starting", By: "the row is written and the session is in the starting set"},
	states.Move{From: "starting", To: "live", By: "the dial, the recording and " + audit.SessionStart + "; the registry knows it"},
	states.Move{From: "starting", To: "ending", By: "the dial or the containers fail (end_reason error)"},
	states.Move{From: "live", To: "ending", By: "the bridge returns: the person, a timeout, " + audit.SessionTerminate + ", a revocation, the ping watch"},
	states.Move{From: "ending", To: "closing", By: "the end frame is sent; the recording is closed and uploaded"},
	states.Move{From: "closing", To: "gone", By: audit.SessionEnd + "; the registry forgets it; containers are torn down"},
).Describe(states.Doc{
	Derivation: "In memory only. The row (`AccessSession.state`) says `live` from `starting` to `closing` and `ended` at `gone`; " +
		"terminate, revocation, the caps and the drain act on the registry, which knows the session from `live` on.",
	Notes: []string{
		"A session in `starting` (dialling, pulling images) cannot be terminated or revoked and is not counted by the caps: an open question of ADR 0047.",
		"The sweep closes a row older than three minutes that is neither in the registry nor in the starting set (`error`), and every open row at start (`gateway_restart`).",
		"Database sessions enter the registry before their containers start; application sessions after. The two therefore differ in what terminate reaches.",
	},
})
