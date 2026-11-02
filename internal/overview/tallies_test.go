// SPDX-License-Identifier: Apache-2.0

package overview

import (
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
)

// The live dashboard said 28 failures; most were one provider's sync, and
// nothing said so (2026-11-03 live audit, Q2). The tallies name the action
// most of the failures were.
func TestFoldTalliesNamesTheCommonestFailure(t *testing.T) {
	a := foldTallies([]audit.Tally{
		{Action: audit.IdPSync, Outcome: audit.Failure, Count: 19},
		{Action: audit.IdPSync, Outcome: audit.Success, Count: 40},
		{Action: audit.UserLogin, Outcome: audit.Failure, Count: 2},
		{Action: audit.SessionConnect, Outcome: audit.Failure, Count: 2},
		{Action: "cli.open", Outcome: audit.Failure, Count: 5},
	})
	if a.Failures != 28 || a.FailedLogins != 2 || a.RefusedConnects != 2 || a.Events != 68 {
		t.Fatalf("counts: %+v", a)
	}
	if a.TopFailure != audit.IdPSync || a.TopFailureCount != 19 {
		t.Fatalf("top failure %q x%d, want idp.sync x19", a.TopFailure, a.TopFailureCount)
	}

	// A tie goes to the action that sorts first, so the answer is stable.
	tie := foldTallies([]audit.Tally{
		{Action: "b.x", Outcome: audit.Failure, Count: 3},
		{Action: "a.x", Outcome: audit.Failure, Count: 3},
	})
	if tie.TopFailure != "a.x" {
		t.Fatalf("tie: %q", tie.TopFailure)
	}
	if none := foldTallies([]audit.Tally{{Action: "a.x", Outcome: audit.Success, Count: 3}}); none.TopFailure != "" || none.TopFailureCount != 0 {
		t.Fatalf("no failures: %+v", none)
	}
}
