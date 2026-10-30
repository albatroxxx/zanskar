// SPDX-License-Identifier: Apache-2.0

package gateway

import "context"

// Revoker ends the live sessions that a change to who may connect has
// withdrawn (ADR 0013, 0036). The admin handlers call it as they make such a
// change, so an open bridge does not outlive the access that admitted it.
// Each method returns how many sessions it ended.
//
// The connect handler implements it; this interface lives here, beside the
// registry, so the handler packages need not import connect.
type Revoker interface {
	// UserRevoked ends every live session of the user: their account was
	// disabled, locked or deleted, their roles changed, or an admin signed
	// them out everywhere.
	UserRevoked(userID string) int
	// Recheck re-checks every live session of the users against the access
	// they hold now (ADR 0036): a session ends when a fresh connect would be
	// refused, or when its clipboard or file transfer would now be off. A
	// shorter idle timeout, maximum or window does not end it. Policy
	// changes, group membership and group deletion call it with the users
	// they touch, after the change is stored.
	Recheck(ctx context.Context, userIDs []string) int
	// TargetDisabled ends every live session on the target or autoscaling
	// instance: an administrator disabled it or moved its address.
	TargetDisabled(targetID string) int
	// TargetTrustLost ends every live session on the target whose pinned
	// host key or certificate was seen to change.
	TargetTrustLost(targetID string) int
	// GrantRevoked ends the user's live sessions over proto on the target
	// or group that the connect gate would refuse now: the just-in-time
	// grant that admitted them was revoked and no standing policy covers
	// them. They end as policy_revoked.
	GrantRevoked(ctx context.Context, userID, targetID, asgID, proto string) int
	// GrantExpired is GrantRevoked for a grant whose window has passed; the
	// sessions end as max_duration, the bound the grant was.
	GrantExpired(ctx context.Context, userID, targetID, asgID, proto string) int
}
