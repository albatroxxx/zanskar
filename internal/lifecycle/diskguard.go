// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"fmt"
	"sync"
	"time"
)

// DiskRefusePercent is how full, by df's Use%, a volume holding the database
// or the recordings may be before new sessions are refused (2026-11-03 live
// audit, idea 8). Every session is recorded and audited (ADR 0006): a full
// disk loses the recording, then the audit rows, mid-session. Refusing new
// sessions keeps what is running whole and fails closed; a session never
// runs unrecorded to save space. The dashboard warns from 80%.
const DiskRefusePercent = 95

// diskGuardEvery is how long a reading stands: Connect asks once per
// session, and a statfs per click is cheap but needless.
const diskGuardEvery = 15 * time.Second

// DiskGuard says whether the gateway's volumes have room for another
// session. Zero value: nothing measured, nothing refused.
type DiskGuard struct {
	DatabasePath   string
	RecordingsPath string
	// measure is diskSpace, replaced by tests.
	measure func(db, rec string) []DiskSpace

	mu   sync.Mutex
	at   time.Time
	last string
}

// Full returns why a new session is refused, or "" when there is room.
func (g *DiskGuard) Full() string {
	if g == nil {
		return ""
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.at.IsZero() && time.Since(g.at) < diskGuardEvery {
		return g.last
	}
	measure := g.measure
	if measure == nil {
		measure = diskSpace
	}
	g.last, g.at = "", time.Now()
	for _, d := range measure(g.DatabasePath, g.RecordingsPath) {
		if pct := usedPercent(d); pct >= DiskRefusePercent {
			g.last = fmt.Sprintf("the gateway's %s disk is %d%% full; new sessions are refused until an administrator frees space, so none runs unrecorded", d.What, pct)
			break
		}
	}
	return g.last
}

// usedPercent is df's Use%: used over used plus what an unprivileged writer
// can still have, rounded up as df rounds it.
func usedPercent(d DiskSpace) int {
	avail := d.UsedBytes + d.FreeBytes
	if avail == 0 {
		return 0
	}
	return int((d.UsedBytes*100 + avail - 1) / avail) // #nosec G115 -- a percentage, at most 100
}
