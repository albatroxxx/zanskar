// SPDX-License-Identifier: Apache-2.0

package gateway

import "context"

// Revoker ends the live sessions that a change to who may connect has
// withdrawn (ADR 0013). The admin handlers call it as they make such a
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
	// PolicyDeleted ends every live session the policy admitted.
	PolicyDeleted(policyID string) int
	// PolicyChanged ends the live sessions the policy admitted that its
	// stored version no longer grants on its own.
	PolicyChanged(ctx context.Context, policyID string) int
	// GroupMembersRemoved ends the live sessions of those users that a
	// policy bound to the group admitted.
	GroupMembersRemoved(ctx context.Context, groupID string, userIDs []string) int
	// GroupDeleted ends the live sessions admitted by every policy bound to
	// the group. Deleting the group deletes those policies, so it must be
	// called while the group still exists.
	GroupDeleted(ctx context.Context, groupID string) int
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
