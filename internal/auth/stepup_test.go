// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestStepUp: the route a host action's guard rests on. A code from the
// session's own authenticator moves the session's proof; anything else is
// refused with the reason, audited as a second-factor check for step_up,
// and the attempts per session are bounded.
func TestStepUp(t *testing.T) {
	e := newEnv(t)
	u := e.bareUser(t, "sam", user.RoleAdmin)
	r := e.sessionFor(t, u, true)
	hdr := csrfOf(r)
	const path = "/api/v1/auth/mfa/step-up"

	// Signed out, or without the CSRF token: never reaches the check.
	if c := e.do("POST", path, map[string]string{"code": "123456"}, nil, nil); c.code != 401 {
		t.Fatalf("anonymous: %d %v", c.code, c.body)
	}
	if c := e.do("POST", path, map[string]string{"code": "123456"}, r.cookie, nil); c.code != 403 {
		t.Fatalf("no CSRF token: %d %v", c.code, c.body)
	}
	// No authenticator enrolled: there is nothing to prove with.
	if c := e.do("POST", path, map[string]string{"code": "123456"}, r.cookie, hdr); c.code != 409 || c.body["code"] != "mfa_not_enrolled" {
		t.Fatalf("not enrolled: %d %v", c.code, c.body)
	}
	right, wrong := enrol(t, e, u)
	// A body that is not a code request.
	if c := e.do("POST", path, map[string]string{"token": "x"}, r.cookie, hdr); c.code != 400 {
		t.Fatalf("unknown field: %d %v", c.code, c.body)
	}
	// A wrong code: refused, audited with the purpose and the reason.
	if c := e.do("POST", path, map[string]string{"code": wrong()}, r.cookie, hdr); c.code != 422 || c.body["code"] != "bad_code" {
		t.Fatalf("wrong code: %d %v", c.code, c.body)
	}
	if ev, d := e.lastEvent(t, audit.UserMFAVerify); ev.Outcome != audit.Failure || d["purpose"] != "step_up" || d["reason"] != "wrong code" || ev.ActorUserID != u.ID {
		t.Fatalf("wrong code audit: %+v %v", ev, d)
	}
	before, err := e.sessions.Lookup(context.Background(), r.cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	// The right code: the session's proof moves to now.
	code := right()
	c := e.do("POST", path, map[string]string{"code": code}, r.cookie, hdr)
	if c.code != 200 || c.body["proved"] != true {
		t.Fatalf("right code: %d %v", c.code, c.body)
	}
	after, err := e.sessions.Lookup(context.Background(), r.cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if !after.MFAAt.After(before.MFAAt) || time.Since(after.MFAAt) > 5*time.Second {
		t.Fatalf("proof not recorded: before %v, after %v", before.MFAAt, after.MFAAt)
	}
	if ev, d := e.lastEvent(t, audit.UserMFAVerify); ev.Outcome != audit.Success || d["purpose"] != "step_up" || d["recovery_code_used"] != false {
		t.Fatalf("success audit: %+v %v", ev, d)
	}
	// The same code again: a code works once, and the audit says so.
	if c := e.do("POST", path, map[string]string{"code": code}, r.cookie, hdr); c.code != 422 {
		t.Fatalf("reused code: %d %v", c.code, c.body)
	}
	if _, d := e.lastEvent(t, audit.UserMFAVerify); d["reason"] != "code already used" {
		t.Fatalf("reused code audit: %v", d)
	}

	// Attempts are bounded per session: a stolen cookie cannot grind codes.
	// A fresh session starts with the limiter's burst; the refusals are
	// audited once, not once per attempt.
	r2 := e.sessionFor(t, u, true)
	hdr2 := csrfOf(r2)
	refused := 0
	for i := 0; i < 20; i++ {
		if c := e.do("POST", path, map[string]string{"code": wrong()}, r2.cookie, hdr2); c.code == 429 {
			refused++
		} else if c.code != 422 {
			t.Fatalf("attempt %d: %d %v", i, c.code, c.body)
		}
	}
	if refused == 0 || refused > 16 {
		t.Fatalf("refused %d of 20 attempts", refused)
	}
	evs, _, err := e.audit.List(context.Background(), audit.Filter{Action: audit.UserMFAVerify})
	if err != nil {
		t.Fatal(err)
	}
	limited := 0
	for _, ev := range evs {
		if strings.Contains(string(ev.Details), `"reason":"rate_limited"`) {
			limited++
		}
	}
	if limited != 1 {
		t.Fatalf("rate_limited audited %d times, want once", limited)
	}
	// The limit is the session's, not the account's: another session of
	// the same account, opened after this one was refused, gets its own
	// attempts.
	r3 := e.sessionFor(t, u, true)
	if c := e.do("POST", path, map[string]string{"code": wrong()}, r3.cookie, csrfOf(r3)); c.code != 422 {
		t.Fatalf("a third session after the second was limited: %d %v", c.code, c.body)
	}
}
