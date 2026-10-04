// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/albatroxxx/zanskar/internal/user"
)

// TestTOTPEnrolmentGuards: until an authenticator is confirmed, enrolling
// again replaces the pending secret; once it is confirmed it cannot be
// replaced or re-confirmed through the API (only an admin reset clears it),
// so a stolen session cannot quietly swap the second factor. Confirming
// before enrolling, or with a malformed body, is refused.
func TestTOTPEnrolmentGuards(t *testing.T) {
	e := newEnv(t)
	unlimited(e)
	e.createUser(t, "dana", "dana has a long passphrase", user.RoleUser)
	r := login(e, "dana", "dana has a long passphrase")
	hdr := map[string]string{"X-CSRF-Token": r.body["csrf_token"].(string)}
	post := func(path string, body any) resp { return e.do("POST", path, body, r.cookie, hdr) }

	if c := post("/api/v1/auth/mfa/totp/confirm", map[string]string{"code": "123456"}); c.code != 409 || c.body["code"] != "not_enrolled" {
		t.Fatalf("confirm before enrolling: %d %v", c.code, c.body)
	}

	first := post("/api/v1/auth/mfa/totp/enroll", nil)
	second := post("/api/v1/auth/mfa/totp/enroll", nil)
	if first.code != 200 || second.code != 200 || first.body["secret"] == second.body["secret"] {
		t.Fatalf("re-enrolling before confirming must replace the secret: %v %v", first.body, second.body)
	}
	stale, _ := totp.GenerateCode(first.body["secret"].(string), time.Now())
	if c := post("/api/v1/auth/mfa/totp/confirm", map[string]string{"code": stale}); c.code != 401 {
		t.Fatalf("a code from the replaced secret: %d, want 401", c.code)
	}
	if c := e.do("POST", "/api/v1/auth/mfa/totp/confirm", nil, r.cookie, hdr); c.code != 400 {
		t.Fatalf("confirm without a body: %d, want 400", c.code)
	}
	code, _ := totp.GenerateCode(second.body["secret"].(string), time.Now())
	if c := post("/api/v1/auth/mfa/totp/confirm", map[string]string{"code": code}); c.code != 200 {
		t.Fatalf("confirm: %d %v", c.code, c.body)
	}

	if c := post("/api/v1/auth/mfa/totp/enroll", nil); c.code != 409 || c.body["code"] != "already_enrolled" {
		t.Fatalf("enrolling over a confirmed authenticator: %d %v", c.code, c.body)
	}
	code, _ = totp.GenerateCode(second.body["secret"].(string), time.Now())
	if c := post("/api/v1/auth/mfa/totp/confirm", map[string]string{"code": code}); c.code != 409 || c.body["code"] != "already_enrolled" {
		t.Fatalf("confirming a confirmed authenticator: %d %v, want 409 already_enrolled", c.code, c.body)
	}
}
