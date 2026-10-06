// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/albatroxxx/zanskar/internal/user"
)

// TestTOTPCodeWorksOnce: an accepted code is refused for the rest of its
// window, and so is any code from an earlier step (RFC 6238 section 5.2). The
// refusal is ErrTOTPReused, which callers see as ErrTOTPBadCode. The code that
// confirms enrolment counts as used.
func TestTOTPCodeWorksOnce(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	u := e.createUser(t, "omar", "omar has a long passphrase", user.RoleAdmin)
	clock := time.Date(2026, 10, 6, 12, 0, 10, 0, time.UTC)
	e.totp.now = func() time.Time { return clock }

	enr, err := e.totp.Enroll(ctx, u.ID, "omar")
	if err != nil {
		t.Fatal(err)
	}
	at := func(d time.Duration) string {
		c, err := totp.GenerateCode(enr.Secret, clock.Add(d))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if _, err := e.totp.Confirm(ctx, u.ID, at(0)); err != nil {
		t.Fatal(err)
	}
	verify := func(code string) error { _, err := e.totp.Verify(ctx, u.ID, code); return err }

	if err := verify(at(0)); !errors.Is(err, ErrTOTPReused) || !errors.Is(err, ErrTOTPBadCode) {
		t.Fatalf("the confirm code again: %v, want ErrTOTPReused wrapping ErrTOTPBadCode", err)
	}
	if err := verify(at(-30 * time.Second)); !errors.Is(err, ErrTOTPReused) {
		t.Fatalf("a code from before the last one accepted: %v, want ErrTOTPReused", err)
	}
	clock = clock.Add(30 * time.Second)
	if err := verify(at(0)); err != nil {
		t.Fatalf("the next step's code: %v", err)
	}
	if err := verify(at(0)); !errors.Is(err, ErrTOTPReused) {
		t.Fatalf("that code a second time: %v, want ErrTOTPReused", err)
	}
	if err := verify("000000"); errors.Is(err, ErrTOTPReused) || !errors.Is(err, ErrTOTPBadCode) {
		t.Fatalf("a wrong code: %v, want ErrTOTPBadCode only", err)
	}
}
