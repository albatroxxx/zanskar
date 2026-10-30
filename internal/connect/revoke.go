// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"time"

	"github.com/albatroxxx/zanskar/internal/access"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/ticket"
)

// Revocation (ADR 0013, 0036). The admin routes that change who may connect
// call the Handler as a gateway.Revoker, and it ends the live sessions the
// change withdrew. A policy, group or membership change re-checks every live
// session of the users it touches against the access they hold now, through
// the same gate a fresh connect passes (Recheck): a session ends when that
// connect would be refused, or when its clipboard or file transfer would now
// be off, and closes as policy_revoked. A shorter idle timeout, maximum or
// window does not end it. An account change ends all of the user's sessions
// as admin_terminated.

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

// Recheck re-checks every live session of the users against the access
// they hold now. A session that cannot be checked, say because its target
// no longer resolves, is kept and logged.
func (h *Handler) Recheck(ctx context.Context, userIDs []string) int {
	want := map[string]bool{}
	for _, id := range userIDs {
		want[id] = true
	}
	sessions := h.live(func(l gateway.Live) bool { return want[l.UserID] })
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
			h.Log.Warn("access changed; live session kept, it could not be checked", "session", l.SessionID, "err", err)
			continue
		}
		d, code, _, err := h.gate().AdmitLive(ctx, l.UserID, ref, l.Protocol, now)
		if err != nil {
			h.Log.Warn("access changed; live session kept, it could not be checked", "session", l.SessionID, "err", err)
			continue
		}
		if code != "" || (l.AllowClipboard && !d.AllowClipboard) || (l.AllowFileTransfer && !d.AllowFileTransfer) {
			withdrawn = append(withdrawn, l)
		}
	}
	n := h.revoke(withdrawn)
	h.logRevoked(n, "access changed")
	return n
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
	return ep.policyRef(), nil
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
