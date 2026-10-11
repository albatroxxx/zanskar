// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"testing"
)

type fakeMFA struct {
	err   error
	reset []string
}

func (f *fakeMFA) Reset(_ context.Context, userID string) error {
	f.reset = append(f.reset, userID)
	return f.err
}

type fakeSignOut struct {
	n   int64
	err error
}

func (f *fakeSignOut) RevokeAllForUser(context.Context, string) (int64, error) { return f.n, f.err }

// TestResetMFA: the one reset behind the console and `zanskar admin
// reset-mfa`. A failed reset signs nobody out; a sign-out that fails after
// the reset is reported as such, so the caller still records the reset.
func TestResetMFA(t *testing.T) {
	ctx := context.Background()
	mfa := &fakeMFA{err: errors.New("db down")}
	if _, err := ResetMFA(ctx, mfa, &fakeSignOut{n: 3}, "u1"); err == nil || errors.Is(err, ErrSignOutAfterReset) {
		t.Fatalf("a failed reset: %v", err)
	}
	mfa.err = nil
	n, err := ResetMFA(ctx, mfa, &fakeSignOut{n: 1, err: errors.New("db down")}, "u1")
	if !errors.Is(err, ErrSignOutAfterReset) || n != 1 {
		t.Fatalf("sign-out failure after a reset: %d %v", n, err)
	}
	if n, err := ResetMFA(ctx, mfa, &fakeSignOut{n: 2}, "u1"); err != nil || n != 2 || len(mfa.reset) != 3 {
		t.Fatalf("reset: %d %v %v", n, err, mfa.reset)
	}
}
