// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/states"
)

// ReviewState is where a policy's access review stands (ADR 0040, ADR 0047):
// never made, made within a quarter, or due again.
type ReviewState string

// Review states.
const (
	ReviewNever   ReviewState = "never_reviewed"
	ReviewCurrent ReviewState = "current"
	ReviewDueNow  ReviewState = "due"
)

// ReviewStateOf derives the review's state from its last date.
func ReviewStateOf(reviewedAt *time.Time, now time.Time) ReviewState {
	switch {
	case reviewedAt == nil:
		return ReviewNever
	case now.Sub(*reviewedAt) > ReviewDue:
		return ReviewDueNow
	}
	return ReviewCurrent
}

// ReviewLifecycle is the review's declared lifecycle.
var ReviewLifecycle = states.New("access review", []string{string(ReviewNever), string(ReviewCurrent), string(ReviewDueNow)},
	states.Move{From: "never_reviewed", To: "current", By: audit.PolicyReview},
	states.Move{From: "current", To: "due", By: "a quarter passes"},
	states.Move{From: "due", To: "current", By: audit.PolicyReview},
).Describe(states.Doc{
	Field:      "review_state",
	Schemas:    []string{"AccessPolicy"},
	Derivation: "`never_reviewed` with no `reviewed_at`, `due` when it is older than ninety days, else `current`. The review view's `due` is the same rule.",
	Notes: []string{
		"Editing a policy does not reset its review.",
	},
})
