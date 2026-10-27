// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"errors"
	"time"

	"github.com/albatroxxx/zanskar/internal/access"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/ticket"
)

// Revocation (ADR 0013, amended 2026-10-11). The admin routes that withdraw
// access call the Handler as a gateway.Revoker, and it ends the live sessions
// that access admitted. Every bridge registers its session under the policy
// that admitted it (gateway.Live.PolicyID), so a policy, group or membership
// change finds exactly those sessions, which close as policy_revoked; an
// account change ends all of the user's sessions as admin_terminated.
//
// A session is judged by the policy that admitted it alone. Access is the
// union of a user's policies, but when the admitting policy stops granting the
// session it ends even if another policy would let the user straight back in;
// they reconnect, and that connect is decided afresh.

var _ gateway.Revoker = (*Handler)(nil)

// revokeTimeout bounds the lookups one revocation makes once it no longer
// follows the admin request's deadline.
const revokeTimeout = 30 * time.Second

// revokeContext detaches a revocation from the admin request that asked for
// it while keeping its values: an admin whose client hangs up just as the
// change is made must not leave running the sessions the change withdrew
// (auth.Recorder detaches its audit insert for the same reason).
func revokeContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return detach(ctx, revokeTimeout)
}

// UserRevoked ends every live session of the user.
func (h *Handler) UserRevoked(userID string) int {
	if h.Registry == nil {
		return 0
	}
	n := h.Registry.TerminateUser(userID)
	h.logRevoked(n, "account changed", "user_id", userID)
	return n
}

// PolicyDeleted ends every live session the policy admitted.
func (h *Handler) PolicyDeleted(policyID string) int {
	n := h.revoke(h.live(func(l gateway.Live) bool { return l.PolicyID == policyID }))
	h.logRevoked(n, "policy deleted", "policy_id", policyID)
	return n
}

// PolicyChanged ends the live sessions the policy admitted that its stored
// version, on its own, no longer grants: it no longer applies to the user
// (bound to them or to a group they are in), it is disabled, it no longer
// allows the session's protocol on the session's target, or none of its time
// windows is open now. A session that cannot be checked, say because its
// target no longer resolves, is kept and logged; if the policy is gone its
// sessions end as for PolicyDeleted.
func (h *Handler) PolicyChanged(ctx context.Context, policyID string) int {
	sessions := h.live(func(l gateway.Live) bool { return l.PolicyID == policyID })
	if len(sessions) == 0 {
		return 0
	}
	ctx, cancel := revokeContext(ctx)
	defer cancel()
	p, err := h.Policies.Get(ctx, policyID)
	if errors.Is(err, policy.ErrNotFound) {
		return h.PolicyDeleted(policyID)
	}
	if err != nil {
		h.Log.Error("policy changed; its live sessions were not checked", "policy_id", policyID, "err", err)
		return 0
	}
	now := time.Now()
	var withdrawn []gateway.Live
	for _, l := range sessions {
		ok, err := h.stillGrants(ctx, p, l, now)
		if err != nil {
			h.Log.Warn("policy changed; live session kept, it could not be checked", "session", l.SessionID, "policy_id", policyID, "err", err)
			continue
		}
		if !ok {
			withdrawn = append(withdrawn, l)
		}
	}
	n := h.revoke(withdrawn)
	h.logRevoked(n, "policy changed", "policy_id", policyID)
	return n
}

// stillGrants reports whether p, on its own, still grants the live session:
// it applies to the session's user, and the connect gate, given that one
// policy, would admit the session's protocol on the session's target now.
// Running the gate rather than Evaluate alone means a policy switched to
// require approval ends the sessions of users without a live grant, and one
// switched to require an authenticator ends those of users without one, the
// same refusals a fresh connect would meet.
func (h *Handler) stillGrants(ctx context.Context, p *policy.Policy, l gateway.Live, now time.Time) (bool, error) {
	applies, err := h.appliesTo(ctx, p.ID, l.UserID)
	if err != nil || !applies {
		return false, err
	}
	ref, err := h.sessionRef(ctx, l.SessionID)
	if err != nil {
		return false, err
	}
	_, code, _, err := h.gate().AdmitPolicies(ctx, l.UserID, []*policy.Policy{p}, ref, l.Protocol, now)
	return code == "" && err == nil, err
}

// gate is the admission every connect passes (access.Gate), shared with the
// applications proxy so the two cannot drift.
func (h *Handler) gate() *access.Gate {
	return &access.Gate{Policies: h.Policies, Grants: h.Access, MFAEnrolled: h.MFAEnrolled}
}

// TargetDisabled ends every live session on the target or instance: an
// administrator disabled it or moved its address, so nothing may stay
// connected to it.
func (h *Handler) TargetDisabled(targetID string) int {
	if h.Registry == nil {
		return 0
	}
	n := h.Registry.TerminateTarget(targetID, gateway.ErrTargetDisabled)
	h.logRevoked(n, "target disabled or changed", "target_id", targetID)
	return n
}

// TargetTrustLost ends every live session on the target whose pinned host
// key or certificate changed: the host may no longer be the one that was
// trusted, and a session already open is the one thing the connect-time
// pin check cannot protect.
func (h *Handler) TargetTrustLost(targetID string) int {
	if h.Registry == nil {
		return 0
	}
	n := h.Registry.TerminateTarget(targetID, gateway.ErrTrustLost)
	h.logRevoked(n, "host key or certificate changed", "target_id", targetID)
	return n
}

// GrantRevoked ends the user's live sessions over proto on the target or
// group whose just-in-time grant was revoked, unless the connect gate would
// still admit them (a standing policy covers the same access, or another
// grant is active). The gate is the same one a fresh connect passes.
func (h *Handler) GrantRevoked(ctx context.Context, userID, targetID, asgID, proto string) int {
	n := h.grantWithdrawn(ctx, userID, targetID, asgID, proto, gateway.ErrGrantRevoked)
	h.logRevoked(n, "grant revoked", "user_id", userID)
	return n
}

// GrantExpired is GrantRevoked for a grant whose window has passed; the
// sessions end as max_duration, the bound the grant was.
func (h *Handler) GrantExpired(ctx context.Context, userID, targetID, asgID, proto string) int {
	n := h.grantWithdrawn(ctx, userID, targetID, asgID, proto, gateway.ErrGrantExpired)
	h.logRevoked(n, "grant expired", "user_id", userID)
	return n
}

func (h *Handler) grantWithdrawn(ctx context.Context, userID, targetID, asgID, proto string, cause error) int {
	// A session on a plain target is registered under that target's id; one
	// on an autoscaling instance under the instance's, so a group is matched
	// once the session's subject is resolved below.
	sessions := h.live(func(l gateway.Live) bool {
		return l.UserID == userID && l.Protocol == proto && (targetID == "" || l.TargetID == targetID)
	})
	if len(sessions) == 0 {
		return 0
	}
	ctx, cancel := revokeContext(ctx)
	defer cancel()
	now := time.Now()
	var withdrawn []gateway.Live
	for _, l := range sessions {
		ref, err := h.sessionRef(ctx, l.SessionID)
		if err != nil {
			h.Log.Warn("grant revoked; live session kept, it could not be checked", "session", l.SessionID, "err", err)
			continue
		}
		if asgID != "" && ref.ASGID != asgID {
			continue
		}
		_, code, _, err := h.gate().Admit(ctx, userID, ref, proto, now)
		if err != nil {
			h.Log.Warn("grant revoked; live session kept, it could not be checked", "session", l.SessionID, "err", err)
			continue
		}
		if code != "" {
			withdrawn = append(withdrawn, l)
		}
	}
	n := 0
	for _, l := range withdrawn {
		if h.Registry.TerminateWithCause(l.SessionID, cause) {
			n++
		}
	}
	return n
}

// GroupMembersRemoved ends the live sessions of those users that a policy
// bound to the group admitted. It is called once they are out of the group.
func (h *Handler) GroupMembersRemoved(ctx context.Context, groupID string, userIDs []string) int {
	out := map[string]bool{}
	for _, id := range userIDs {
		out[id] = true
	}
	n := h.revokeGroupSessions(ctx, groupID, h.live(func(l gateway.Live) bool { return out[l.UserID] && l.PolicyID != "" }))
	h.logRevoked(n, "removed from group", "group_id", groupID)
	return n
}

// GroupDeleted ends the live sessions admitted by any policy bound to the
// group. It is called before the group is deleted, which deletes those
// policies too.
func (h *Handler) GroupDeleted(ctx context.Context, groupID string) int {
	n := h.revokeGroupSessions(ctx, groupID, h.live(func(l gateway.Live) bool { return l.PolicyID != "" }))
	h.logRevoked(n, "group deleted", "group_id", groupID)
	return n
}

// revokeGroupSessions ends those of sessions that a policy bound to the group
// admitted.
func (h *Handler) revokeGroupSessions(ctx context.Context, groupID string, sessions []gateway.Live) int {
	if len(sessions) == 0 {
		return 0
	}
	ctx, cancel := revokeContext(ctx)
	defer cancel()
	pols, err := h.Policies.ForGroup(ctx, groupID)
	if err != nil {
		h.Log.Error("group changed; its live sessions were not checked", "group_id", groupID, "err", err)
		return 0
	}
	bound := map[string]bool{}
	for _, p := range pols {
		bound[p.ID] = true
	}
	var withdrawn []gateway.Live
	for _, l := range sessions {
		if bound[l.PolicyID] {
			withdrawn = append(withdrawn, l)
		}
	}
	return h.revoke(withdrawn)
}

// appliesTo reports whether the policy is enabled and bound to the user or to
// a group they are in: ForUser, the question the connect gate asks.
func (h *Handler) appliesTo(ctx context.Context, policyID, userID string) (bool, error) {
	pols, err := h.Policies.ForUser(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, p := range pols {
		if p.ID == policyID {
			return true, nil
		}
	}
	return false, nil
}

// sessionRef puts what a live session is connected to in the policy engine's
// terms. Its row names the target or the autoscaling instance, resolved the
// way the bridge resolved its ticket.
func (h *Handler) sessionRef(ctx context.Context, sessionID string) (policy.TargetRef, error) {
	s, err := h.Sessions.Get(ctx, sessionID)
	if err != nil {
		return policy.TargetRef{}, err
	}
	ep, err := h.resolveGrant(ctx, &ticket.Grant{TargetID: s.TargetID, ASGInstanceID: s.ASGInstanceID})
	if err != nil {
		return policy.TargetRef{}, err
	}
	id, asgID, tags := ep.policyRef()
	return policy.TargetRef{ID: id, ASGID: asgID, Tags: tags}, nil
}

// live snapshots the registered sessions keep selects.
func (h *Handler) live(keep func(gateway.Live) bool) []gateway.Live {
	if h.Registry == nil {
		return nil
	}
	var out []gateway.Live
	for _, l := range h.Registry.List() {
		if keep(l) {
			out = append(out, l)
		}
	}
	return out
}

// revoke ends sessions as policy_revoked and returns how many were still
// live to end.
func (h *Handler) revoke(sessions []gateway.Live) int {
	n := 0
	for _, l := range sessions {
		if h.Registry.TerminateWithCause(l.SessionID, gateway.ErrPolicyRevoked) {
			n++
		}
	}
	return n
}

func (h *Handler) logRevoked(n int, why string, attrs ...any) {
	if n > 0 {
		h.Log.Info("live sessions ended", append([]any{"count", n, "why", why}, attrs...)...)
	}
}
