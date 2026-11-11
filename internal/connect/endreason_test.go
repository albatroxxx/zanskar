// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"testing"

	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/session"
)

// TestCancelReasonsAreDeclaredEndReasons (ADR 0047, 2026-11-09): every end
// reason the registry writes for a cancellation is one the session package
// declares, so the OpenAPI enum, the console's words and the sweep's list
// speak of the same twelve. target_deleted was written and rendered for two
// releases without being declared. The registry cannot import session, so
// the check lives here, where both are known.
func TestCancelReasonsAreDeclaredEndReasons(t *testing.T) {
	causes := map[error]string{
		gateway.ErrTargetLost:      session.EndTargetLost,
		gateway.ErrPolicyRevoked:   session.EndPolicyRevoked,
		gateway.ErrGrantRevoked:    session.EndPolicyRevoked,
		gateway.ErrGrantExpired:    session.EndMaxDuration,
		gateway.ErrTargetDisabled:  session.EndAdminTerminated,
		gateway.ErrTargetDeleted:   session.EndTargetDeleted,
		gateway.ErrTrustLost:       session.EndTrustLost,
		gateway.ErrGatewayRestart:  session.EndGatewayRestart,
		gateway.ErrAdminTerminated: session.EndAdminTerminated,
	}
	declared := map[string]bool{}
	for _, r := range session.EndReasons {
		declared[r] = true
	}
	for cause, want := range causes {
		ctx, cancel := context.WithCancelCause(context.Background())
		cancel(cause)
		got, msg := gateway.CancelReason(ctx)
		if got != want {
			t.Errorf("%v: end reason %q, want %q", cause, got, want)
		}
		if !declared[got] {
			t.Errorf("%v: end reason %q is not in session.EndReasons", cause, got)
		}
		if msg == "" {
			t.Errorf("%v: no sentence for the person", cause)
		}
	}
}
