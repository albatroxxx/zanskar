// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/states"
)

// ChannelLifecycle is a notification channel's declared lifecycle (ADR 0039,
// ADR 0047): on or off by the row, and how its deliveries are going by the
// notifier's memory.
var ChannelLifecycle = states.New("notification channel",
	[]string{"on", "off", "failing"},
	states.Move{From: "on", To: "off", By: audit.NotifyChannelUpdate + " with enabled false"},
	states.Move{From: "off", To: "on", By: audit.NotifyChannelUpdate + " with enabled true (the backlog since it went off is delivered)"},
	states.Move{From: "on", To: "failing", By: "a delivery fails; retried with a backoff up to 5 min"},
	states.Move{From: "failing", To: "on", By: "a pass delivers at least one message"},
	states.Move{From: "failing", To: "off", By: audit.NotifyChannelUpdate + " with enabled false"},
).Describe(states.Doc{
	Derivation: "`enabled` on the row; `status{last_sent_at, last_error, last_error_at}` from memory: `failing` is a `last_error` that no later delivery cleared.",
	Notes: []string{
		"Delivery health is lost at restart; a stale error outlives a fix until a new matching event is delivered, and a passing Test does not clear it.",
	},
})
