// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"testing"
)

// TestRegistryEndsEachSessionOnce: two changes that withdraw the same session
// at once (a target disabled while its policy is edited, say) count it once
// between them, and the first cause is the one the bridge reads. Terminate
// still reports the session as found here while it is ending, since its
// caller asks whether this process holds it.
func TestRegistryEndsEachSessionOnce(t *testing.T) {
	r := NewRegistry()
	ctx := r.Add(context.Background(), Live{SessionID: "s1", UserID: "u", TargetID: "t", Protocol: "ssh", PolicyID: "p"})
	r.Add(context.Background(), Live{SessionID: "s2", UserID: "u", TargetID: "t", Protocol: "ssh"})

	if n := r.TerminateTarget("t", ErrTrustLost); n != 2 {
		t.Fatalf("first TerminateTarget ended %d, want 2", n)
	}
	if n := r.TerminateTarget("t", ErrTargetDisabled); n != 0 {
		t.Fatalf("second TerminateTarget ended %d, want 0", n)
	}
	if n := r.TerminateUser("u"); n != 0 {
		t.Fatalf("TerminateUser after the target ended them: %d, want 0", n)
	}
	if r.TerminateWithCause("s1", ErrPolicyRevoked) {
		t.Fatal("TerminateWithCause counted a session already ending")
	}
	if !r.Terminate("s1") {
		t.Fatal("Terminate must still find a session that is ending here")
	}
	if reason, _ := CancelReason(ctx); reason != "trust_lost" || !errors.Is(context.Cause(ctx), ErrTrustLost) {
		t.Fatalf("the first cause must stand: %s %v", reason, context.Cause(ctx))
	}
	r.Remove("s1")
	r.Remove("s2")
	if r.Terminate("s1") || r.TerminateTarget("t", ErrTargetDisabled) != 0 {
		t.Fatal("nothing to end once the bridges have left")
	}
}

// TestCancelReasons: each cause maps to the end reason the row and the
// browser dialog carry.
func TestCancelReasons(t *testing.T) {
	for cause, want := range map[error]string{
		ErrAdminTerminated: "admin_terminated", ErrTargetDisabled: "admin_terminated", ErrTargetLost: "target_lost",
		ErrPolicyRevoked: "policy_revoked", ErrGrantRevoked: "policy_revoked", ErrGrantExpired: "max_duration", ErrTrustLost: "trust_lost", ErrGatewayRestart: "gateway_restart",
	} {
		ctx, cancel := context.WithCancelCause(context.Background())
		cancel(cause)
		if got, msg := CancelReason(ctx); got != want || msg == "" {
			t.Errorf("%v: %q %q, want %q with words", cause, got, msg, want)
		}
	}
}
