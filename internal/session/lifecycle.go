// SPDX-License-Identifier: Apache-2.0

package session

import (
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/states"
)

// EndTargetDeleted: the target or autoscaling group was retired while the
// session ran (ADR 0019; ADR 0036, amended 2026-10-30). The registry writes
// it (gateway.CancelReason, which cannot import this package); it is declared
// here so the end reasons are one list (2026-11-09: the console rendered it
// while the constants and the OpenAPI enum did not know it).
const EndTargetDeleted = "target_deleted"

// EndReasons is every value the gateway writes to access_sessions.end_reason,
// the OpenAPI enum and docs/lifecycles.md included.
var EndReasons = []string{EndUserExit, EndIdleTimeout, EndMaxDuration, EndAdminTerminated, EndPolicyRevoked, EndTrustLost,
	EndGatewayRestart, EndTargetLost, EndTargetDeleted, EndFailover, EndError, EndNoWatcher}

// State is what holds of a session now (ADR 0047): live, or ended with an
// end reason. The row has no status column; the state is read off ended_at.
type State string

// Session states.
const (
	StateLive  State = "live"
	StateEnded State = "ended"
)

// StateOf derives a session's state from its end time.
func StateOf(endedAt *time.Time) State {
	if endedAt != nil {
		return StateEnded
	}
	return StateLive
}

// Lifecycle is the session's declared lifecycle.
var Lifecycle = states.New("session", []string{string(StateLive), string(StateEnded)},
	states.Move{From: "live", To: "ended", By: "the bridge returns (end_reason says why)"},
	states.Move{From: "live", To: "ended", By: audit.SessionTerminate},
	states.Move{From: "live", To: "ended", By: "the sweep: error, or gateway_restart at start"},
).Describe(states.Doc{
	Field:   "state",
	Schemas: []string{"OwnSession", "AccessSession"},
	Derivation: "`live` while `ended_at` is null, else `ended`; `end_reason` says why and `end_detail` what was said. " +
		"The row cannot tell a session that is still starting (dialling, pulling images) or still closing (uploading its recording) from one that is bridging: " +
		"those phases live in the gateway's registry and starting set, and the sweep closes a row older than three minutes that neither knows.",
	Notes: []string{
		"End reasons: `" + joinReasons() + "`.",
		"`no_watcher` is kept for rows 1.15.0 ended under four eyes; nothing writes it since 1.16.0.",
		"A session's recording has a lifecycle of its own, below; `recording_state` carries it on the session for reviewers.",
	},
})

func joinReasons() string {
	out := ""
	for i, r := range EndReasons {
		if i > 0 {
			out += "`, `"
		}
		out += r
	}
	return out
}

// RecordingState is what holds of a session's recording now.
type RecordingState string

// Recording states. A recording is written while the session runs, finished
// when its bridge or the sweep closes it, lost when its session ended with
// it still open, purged when retention deleted the file, and discarded when
// a desktop session drew nothing and the gateway deleted it at once.
const (
	RecordingWriting   RecordingState = "recording"
	RecordingFinished  RecordingState = "finished"
	RecordingLost      RecordingState = "lost"
	RecordingPurged    RecordingState = "purged"
	RecordingDiscarded RecordingState = "discarded"
)

// RecordingStateOf derives a recording's state from its row and whether its
// session has ended.
func RecordingStateOf(finishedAt, purgedAt, discardedAt *time.Time, sessionEnded bool) RecordingState {
	switch {
	case discardedAt != nil:
		return RecordingDiscarded
	case purgedAt != nil:
		return RecordingPurged
	case finishedAt != nil:
		return RecordingFinished
	case sessionEnded:
		return RecordingLost
	}
	return RecordingWriting
}

// RecordingLifecycle is the recording's declared lifecycle.
var RecordingLifecycle = states.New("recording",
	[]string{string(RecordingWriting), string(RecordingFinished), string(RecordingLost), string(RecordingPurged), string(RecordingDiscarded)},
	states.Move{From: "recording", To: "finished", By: "the bridge closes it: size, digest, finished_at"},
	states.Move{From: "recording", To: "lost", By: "the session ended with it still open (" + audit.RecordingLost + ")"},
	states.Move{From: "lost", To: "finished", By: "the sweep measures what storage holds"},
	states.Move{From: "finished", To: "purged", By: audit.RecordingPurge},
	states.Move{From: "lost", To: "purged", By: audit.RecordingPurge + ", aged from the session's end"},
	states.Move{From: "finished", To: "discarded", By: "a desktop session drew no frame"},
).Describe(states.Doc{
	Field:   "state",
	Schemas: []string{"Recording"},
	Derivation: "`discarded` when `discarded_at` is set, else `purged` when `purged_at` is set, else `finished` when `finished_at` is set, " +
		"else `lost` when the session has ended, else `recording`. A session carries the same word as `recording_state` (reviewers only).",
	Notes: []string{
		"A discarded recording is left out of the sessions list by the join; its row stays so the events that name it resolve.",
		"`lost` is also an audit event (`recording.lost`) and a notification; the row itself keeps `finished_at` null.",
	},
})
