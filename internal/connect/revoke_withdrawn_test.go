// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/access"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/session"
)

// grant approves a just-in-time grant for alice over ssh on the target,
// good for an hour from now, and returns its id.
func (f *connectFixture) grant(t *testing.T, targetID string) string {
	t.Helper()
	req := &access.Request{UserID: f.alice.ID, TargetID: targetID, Protocol: "ssh", Reason: "test", RequestedMinutes: 60}
	if err := f.access.Create(f.ctx, req); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	if _, err := f.access.Decide(f.ctx, req.ID, f.alice.ID, access.StatusApproved, "", &expires, req.RequestedMinutes); err != nil {
		t.Fatal(err)
	}
	return req.ID
}

// endedAs asserts the reason a session's row and its session.end event give.
func (f *connectFixture) endedAs(t *testing.T, sessionID, want string) {
	t.Helper()
	if row, audited := f.endedWith(t, sessionID); row != want || audited != want {
		t.Fatalf("session %s ended %q (session.end says %q), want %q", sessionID, row, audited, want)
	}
}

// TestRevokeTargetDisabled: an administrator disables the target alice is
// connected to (or moves its address). The session ends as admin_terminated
// at once rather than at its idle or maximum limit; a session on another
// target is untouched.
func TestRevokeTargetDisabled(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	ctx := revokeCtx(t)
	id := r.liveShell(t, ctx)
	other := r.h.Registry.Add(context.Background(), gateway.Live{SessionID: "other", UserID: r.alice.ID, TargetID: "elsewhere", Protocol: "ssh"})
	t.Cleanup(func() { r.h.Registry.Remove("other") })

	if n := r.h.TargetDisabled(r.targetID); n != 1 {
		t.Fatalf("TargetDisabled ended %d session(s), want 1", n)
	}
	r.endedAs(t, id, session.EndAdminTerminated)
	if other.Err() != nil {
		t.Fatal("a session on another target was ended")
	}
	r.gone(t, id)
	if n := r.h.TargetDisabled(r.targetID); n != 0 {
		t.Fatalf("a second disable ended %d session(s), want 0", n)
	}
}

// gone waits for the bridge to take its session out of the registry, which
// it does last, after the row and the audit event are written.
func (f *connectFixture) gone(t *testing.T, sessionID string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := f.h.Registry.Get(sessionID); !ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("session %s is still in the registry", sessionID)
}

// TestRevokeTargetTrustLost: a probe finds the target's host key changed.
// The host may not be the one that was trusted, so the session already open
// on it ends as trust_lost, the reason the row and the audit event carry.
func TestRevokeTargetTrustLost(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	ctx := revokeCtx(t)
	id := r.liveShell(t, ctx)

	if n := r.h.TargetTrustLost(r.targetID); n != 1 {
		t.Fatalf("TargetTrustLost ended %d session(s), want 1", n)
	}
	r.endedAs(t, id, session.EndTrustLost)
}

// TestRevokeGrantRevoked: alice reaches the shell on a just-in-time grant
// alone. Revoking the grant ends the session as policy_revoked; a session of
// hers on another target is not looked at, and when a standing policy also
// covers the target the session stays, because a fresh connect would be
// admitted too.
func TestRevokeGrantRevoked(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	ctx := revokeCtx(t)
	// Only the approval-gated "jit" policy covers tier=jit.
	tg, err := r.h.Targets.Get(r.ctx, r.targetID)
	if err != nil {
		t.Fatal(err)
	}
	tg.Tags = map[string]string{"tier": "jit"}
	if err := r.h.Targets.Update(r.ctx, tg); err != nil {
		t.Fatal(err)
	}
	grant := r.grant(t, r.targetID)
	id := r.liveShell(t, ctx)
	other := r.h.Registry.Add(context.Background(), gateway.Live{SessionID: "other", UserID: r.alice.ID, TargetID: "elsewhere", Protocol: "ssh"})
	t.Cleanup(func() { r.h.Registry.Remove("other") })

	// The grant is still active: nothing to end.
	if n := r.h.GrantRevoked(r.ctx, r.alice.ID, r.targetID, "", "ssh"); n != 0 {
		t.Fatalf("GrantRevoked with the grant active ended %d session(s), want 0", n)
	}
	if _, err := r.access.Revoke(r.ctx, grant, "done"); err != nil {
		t.Fatal(err)
	}
	if n := r.h.GrantRevoked(r.ctx, r.alice.ID, r.targetID, "", "ssh"); n != 1 {
		t.Fatalf("GrantRevoked ended %d session(s), want 1", n)
	}
	r.revoked(t, id)
	if other.Err() != nil {
		t.Fatal("a session on another target was ended")
	}

	// Standing access beside the grant: the session survives the revoke.
	tg.Tags = map[string]string{"tier": "jit", "env": "test"}
	if err := r.h.Targets.Update(r.ctx, tg); err != nil {
		t.Fatal(err)
	}
	grant = r.grant(t, r.targetID)
	id = r.liveShell(t, ctx)
	if _, err := r.access.Revoke(r.ctx, grant, "done"); err != nil {
		t.Fatal(err)
	}
	if n := r.h.GrantRevoked(r.ctx, r.alice.ID, r.targetID, "", "ssh"); n != 0 {
		t.Fatalf("GrantRevoked under standing access ended %d session(s), want 0", n)
	}
	r.stillLive(t, id)
}

// TestRevokeGrantExpired: a grant that ran out ends the session it admitted
// as max_duration, the bound the grant was, not as a revocation.
func TestRevokeGrantExpired(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	ctx := revokeCtx(t)
	tg, err := r.h.Targets.Get(r.ctx, r.targetID)
	if err != nil {
		t.Fatal(err)
	}
	tg.Tags = map[string]string{"tier": "jit"}
	if err := r.h.Targets.Update(r.ctx, tg); err != nil {
		t.Fatal(err)
	}
	grant := r.grant(t, r.targetID)
	id := r.liveShell(t, ctx)
	// The sweeper flips the row before it asks; stand in for it.
	if _, err := r.access.Revoke(r.ctx, grant, "stand-in for expiry"); err != nil {
		t.Fatal(err)
	}
	if n := r.h.GrantExpired(r.ctx, r.alice.ID, r.targetID, "", "ssh"); n != 1 {
		t.Fatalf("GrantExpired ended %d session(s), want 1", n)
	}
	r.endedAs(t, id, session.EndMaxDuration)
}
