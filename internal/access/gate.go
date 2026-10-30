// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"time"

	"github.com/albatroxxx/zanskar/internal/policy"
)

// Gate is the admission every session passes, when it is asked for and
// again when it starts: the caller's policies must allow the protocol on the
// target now, an approval-gated grant must be live (ADR 0018), and a policy
// that requires an authenticator must find one enrolled. The connect flow
// and the applications proxy (ADR 0033) share it, so the two cannot drift.
type Gate struct {
	Policies *policy.Repo
	// Grants holds the just-in-time grants; nil leaves every approval-gated
	// policy standing.
	Grants *Repo
	// MFAEnrolled reports whether the user has an authenticator; nil skips
	// the check.
	MFAEnrolled func(ctx context.Context, userID string) (bool, error)
}

// Refusal codes Admit returns, as the API answers them.
const (
	CodePolicyDenied     = "policy_denied"
	CodeApprovalRequired = "approval_required"
	CodeMFARequired      = "mfa_required_by_policy"
)

// Admit evaluates the user's policies for proto on ref. It returns the
// allowing decision, or the code and message of a refusal; err is an
// infrastructure failure, not a refusal.
func (g *Gate) Admit(ctx context.Context, userID string, ref policy.TargetRef, proto string, now time.Time) (policy.Decision, string, string, error) {
	return g.admit(ctx, userID, ref, proto, now, policy.Evaluate)
}

// AdmitLive is Admit for a session already running, as revocation re-checks
// it (ADR 0036): the same grant and authenticator checks a fresh connect
// meets, but every time window counts as open, so a shut window does not
// pull the session.
func (g *Gate) AdmitLive(ctx context.Context, userID string, ref policy.TargetRef, proto string, now time.Time) (policy.Decision, string, string, error) {
	return g.admit(ctx, userID, ref, proto, now, policy.EvaluateLive)
}

func (g *Gate) admit(ctx context.Context, userID string, ref policy.TargetRef, proto string, now time.Time,
	evaluate func([]*policy.Policy, policy.TargetRef, string, time.Time) policy.Decision) (policy.Decision, string, string, error) {
	pols, err := g.Policies.ForUser(ctx, userID)
	if err != nil {
		return policy.Decision{}, "", "", err
	}
	d := evaluate(pols, ref, proto, now)
	if !d.Allowed {
		return d, CodePolicyDenied, d.Reason, nil
	}
	// Approval-gated access needs a live grant (ADR 0018); a standing policy
	// covering the same target would have set RequireApproval false above.
	if d.RequireApproval && g.Grants != nil {
		granted, err := g.Grants.HasActiveGrant(ctx, userID, ref.ID, ref.ASGID, proto, now)
		if err != nil {
			return d, "", "", err
		}
		if !granted {
			return d, CodeApprovalRequired, "access to this target requires an approved request", nil
		}
	}
	if d.RequireMFA && g.MFAEnrolled != nil {
		enrolled, err := g.MFAEnrolled(ctx, userID)
		if err != nil {
			return d, "", "", err
		}
		if !enrolled {
			return d, CodeMFARequired, "this policy requires an enrolled authenticator", nil
		}
	}
	return d, "", "", nil
}
