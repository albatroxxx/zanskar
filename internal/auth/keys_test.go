// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/user"
)

// The gateway's public address in these tests, and its host: the relying
// party every key belongs to (ADR 0028).
const (
	testOrigin = "https://gw.example.test"
	testRPID   = "gw.example.test"
)

// keysOn gives the handler keys at testOrigin, over the env's own app store.
func (e *env) keysOn(t *testing.T) *Factors {
	t.Helper()
	f := NewFactors(e.db, e.totp, NewKeys(e.db, testOrigin, "Zanskar Test"))
	e.handler.Factors = f
	return f
}

// begin starts a key ceremony for purpose on the session r and returns the
// options, failing the test unless the gateway answered 200.
func (e *env) begin(t *testing.T, r resp, purpose string) map[string]any {
	t.Helper()
	c := e.do("POST", "/api/v1/auth/mfa/webauthn/begin", map[string]string{"purpose": purpose}, r.cookie, csrfOf(r))
	if c.code != 200 {
		t.Fatalf("begin %s: %d %v", purpose, c.code, c.body)
	}
	return c.body
}

// addKey registers k on the full session r and returns the gateway's answer.
func (e *env) addKey(t *testing.T, r resp, k *softKey, name string) resp {
	t.Helper()
	opts := e.begin(t, r, PurposeRegister)
	return e.do("POST", "/api/v1/auth/mfa/webauthn/register", map[string]any{"name": name, "credential": k.create(t, opts)}, r.cookie, csrfOf(r))
}

// withCookie is r carrying the cookie a rotation sent, when one was sent.
func withCookie(r resp, c resp) resp {
	if c.cookie != nil {
		r.cookie = c.cookie
	}
	return r
}

func TestKeysOffWithoutAHostName(t *testing.T) {
	db := storetest.Open(t)
	for _, tc := range []struct{ url, want string }{
		{"", "No public address is set (ZANSKAR_PUBLIC_URL)."},
		{"https://203.0.113.9", "The public address is an IP address; keys need a host name."},
		{"https://[2001:db8::1]:8443", "The public address is an IP address; keys need a host name."},
		{testOrigin, ""},
	} {
		k := NewKeys(db, tc.url, "Zanskar Test")
		if k.Off() != tc.want {
			t.Errorf("%q: off %q, want %q", tc.url, k.Off(), tc.want)
		}
		if tc.want != "" {
			if _, err := k.BeginAssertion(context.Background(), "s", "u", PurposeStepUp); !errors.Is(err, ErrKeysOff) {
				t.Errorf("%q: begin %v, want ErrKeysOff", tc.url, err)
			}
		}
	}
}

// TestKeySignInAndStepUp: a key registered as a first factor signs in and
// steps up, each answer works once, and a wrong origin or a counter that
// went back is refused as a wrong code and audited as what it was.
func TestKeySignInAndStepUp(t *testing.T) {
	e := newEnv(t)
	e.keysOn(t)
	u := e.bareUser(t, "kim", user.RoleAdmin)
	key := newSoftKey(t)

	// A first factor from a full session of an account a provider signs in:
	// the recent sign-in is enough, and the recovery codes come with it.
	full := e.sessionFor(t, u, true)
	c := e.addKey(t, full, key, "YubiKey 5C")
	codes, _ := c.body["recovery_codes"].([]any)
	if c.code != 200 || len(codes) != recoveryCodeCount || c.body["key"].(map[string]any)["name"] != "YubiKey 5C" {
		t.Fatalf("register: %d %v", c.code, c.body)
	}
	if ev, d := e.lastEvent(t, audit.UserKeyRegister); ev.Outcome != audit.Success || d["first_factor"] != true {
		t.Fatalf("register audit: %+v %v", ev, d)
	}

	// The next sign-in owes its second step and is offered the key.
	part := e.sessionFor(t, u, false)
	me := e.do("GET", "/api/v1/auth/me", nil, part.cookie, nil)
	if me.body["pending"] != "verify" || me.body["second_factor"].(map[string]any)["keys"] != float64(1) {
		t.Fatalf("me: %v", me.body)
	}
	v := e.do("POST", "/api/v1/auth/mfa/webauthn/verify", map[string]any{"credential": key.get(t, e.begin(t, part, PurposeSignIn))}, part.cookie, csrfOf(part))
	if v.code != 200 || v.body["status"] != "ok" {
		t.Fatalf("verify: %d %v", v.code, v.body)
	}
	if _, d := e.lastLogin(t); d["stage"] != "complete" || d["mfa"] != "webauthn" {
		t.Fatalf("login audit: %v", d)
	}
	signedIn := withCookie(part, v)

	// A step-up with the key; the same answer again finds no challenge.
	ans := key.get(t, e.begin(t, signedIn, PurposeStepUp))
	if s := e.do("POST", "/api/v1/auth/mfa/step-up", map[string]any{"credential": ans}, signedIn.cookie, csrfOf(signedIn)); s.code != 200 || s.body["proved"] != true {
		t.Fatalf("step-up: %d %v", s.code, s.body)
	}
	if _, d := e.lastEvent(t, audit.UserMFAVerify); d["purpose"] != "step_up" || d["method"] != "webauthn" {
		t.Fatalf("step-up audit: %v", d)
	}
	if s := e.do("POST", "/api/v1/auth/mfa/step-up", map[string]any{"credential": ans}, signedIn.cookie, csrfOf(signedIn)); s.code != 409 || s.body["code"] != "key_request_expired" {
		t.Fatalf("reused answer: %d %v", s.code, s.body)
	}

	// A counter that went back: a copy of the key may exist.
	opts := e.begin(t, signedIn, PurposeStepUp)
	high := key.count
	key.count = 1
	if s := e.do("POST", "/api/v1/auth/mfa/step-up", map[string]any{"credential": key.sign(t, challengeOf(t, opts))}, signedIn.cookie, csrfOf(signedIn)); s.code != 422 || s.body["code"] != "bad_key" {
		t.Fatalf("counter back: %d %v", s.code, s.body)
	}
	if _, d := e.lastEvent(t, audit.UserMFAVerify); d["reason"] != "key counter went back" {
		t.Fatalf("counter audit: %v", d)
	}

	// The same key at a look-alike address: its signature names the wrong
	// origin, which is what phishing would give.
	key.count = high
	phished := *key
	phished.origin = "https://gw-example.test"
	if s := e.do("POST", "/api/v1/auth/mfa/step-up", map[string]any{"credential": phished.get(t, e.begin(t, signedIn, PurposeStepUp))}, signedIn.cookie, csrfOf(signedIn)); s.code != 422 {
		t.Fatalf("wrong origin: %d %v", s.code, s.body)
	}
	if _, d := e.lastEvent(t, audit.UserMFAVerify); d["reason"] != "key not accepted" {
		t.Fatalf("wrong origin audit: %v", d)
	}
}

// TestKeyOnlyAccountCannotSkipItsKey: an account whose only second factor is
// a key has no authenticator app, so its password alone once could have
// enrolled one and passed the sign-in with it. A sign-in that owes the
// factor it has proves it; it adds none. Its recovery codes still work.
func TestKeyOnlyAccountCannotSkipItsKey(t *testing.T) {
	e := newEnv(t)
	e.keysOn(t)
	u := e.bareUser(t, "lee", user.RoleAdmin)
	c := e.addKey(t, e.sessionFor(t, u, true), newSoftKey(t), "Laptop")
	codes, _ := c.body["recovery_codes"].([]any)
	if c.code != 200 || len(codes) == 0 {
		t.Fatalf("register: %d %v", c.code, c.body)
	}

	part := e.sessionFor(t, u, false)
	for _, step := range []struct {
		path string
		body any
	}{
		{"/api/v1/auth/mfa/totp/enroll", map[string]string{}},
		{"/api/v1/auth/mfa/totp/confirm", map[string]string{"code": "123456"}},
		{"/api/v1/auth/mfa/webauthn/begin", map[string]string{"purpose": PurposeRegister}},
		{"/api/v1/auth/mfa/webauthn/register", map[string]any{"name": "x", "credential": json.RawMessage(`{}`)}},
	} {
		if r := e.do("POST", step.path, step.body, part.cookie, csrfOf(part)); r.code != 403 || r.body["code"] != "verify_first" {
			t.Fatalf("%s on a sign-in that owes its key: %d %v", step.path, r.code, r.body)
		}
	}
	// An app-shaped code is just a wrong code: there is no app.
	if r := e.verifyCode(part, "123456"); r.code != 401 || r.body["code"] != "invalid_code" {
		t.Fatalf("app code: %d %v", r.code, r.body)
	}
	if r := e.verifyCode(part, codes[0].(string)); r.code != 200 || r.body["status"] != "ok" {
		t.Fatalf("recovery code: %d %v", r.code, r.body)
	}
	if _, d := e.lastLogin(t); d["mfa"] != "recovery_code" {
		t.Fatalf("login audit: %v", d)
	}
}

// TestAnotherKeyNeedsAFreshProof: beside a factor the account has, adding a
// key asks for a step-up first, brings no new recovery codes, and signs the
// account's other sessions out; removing one asks for a step-up too, and
// the last factor of an account that must have one stays.
func TestAnotherKeyNeedsAFreshProof(t *testing.T) {
	e := newEnv(t)
	e.keysOn(t)
	u := e.bareUser(t, "max", user.RoleAdmin)
	first := newSoftKey(t)
	if c := e.addKey(t, e.sessionFor(t, u, true), first, "First"); c.code != 200 {
		t.Fatalf("first key: %d %v", c.code, c.body)
	}
	full := e.sessionFor(t, u, true)
	other := e.sessionFor(t, u, true)
	if c := e.do("POST", "/api/v1/auth/mfa/webauthn/begin", map[string]string{"purpose": PurposeRegister}, full.cookie, csrfOf(full)); c.code != 403 || c.body["code"] != "step_up_required" {
		t.Fatalf("begin without a fresh proof: %d %v", c.code, c.body)
	}
	if s := e.do("POST", "/api/v1/auth/mfa/step-up", map[string]any{"credential": first.get(t, e.begin(t, full, PurposeStepUp))}, full.cookie, csrfOf(full)); s.code != 200 {
		t.Fatalf("step-up: %d %v", s.code, s.body)
	}
	c := e.addKey(t, full, newSoftKey(t), "Second")
	if c.code != 200 || c.body["recovery_codes"] != nil {
		t.Fatalf("second key: %d %v", c.code, c.body)
	}
	if _, d := e.lastEvent(t, audit.UserKeyRegister); d["first_factor"] != false || d["other_sessions_revoked"] != float64(2) {
		t.Fatalf("second key audit: %v", d)
	}
	if r := e.do("GET", "/api/v1/auth/me", nil, other.cookie, nil); r.code != 401 {
		t.Fatalf("another session survived a new key: %d", r.code)
	}
	list := e.do("GET", "/api/v1/auth/mfa/webauthn/keys", nil, full.cookie, nil)
	items, _ := list.body["items"].([]any)
	if list.code != 200 || len(items) != 2 || list.body["keys_off"] != "" {
		t.Fatalf("list: %d %v", list.code, list.body)
	}
	secondID := items[1].(map[string]any)["id"].(string)
	firstID := items[0].(map[string]any)["id"].(string)
	if r := e.do("PATCH", "/api/v1/auth/mfa/webauthn/keys/"+secondID, map[string]string{"name": "  "}, full.cookie, csrfOf(full)); r.code != 400 {
		t.Fatalf("blank name: %d %v", r.code, r.body)
	}
	if r := e.do("PATCH", "/api/v1/auth/mfa/webauthn/keys/"+secondID, map[string]string{"name": "Spare"}, full.cookie, csrfOf(full)); r.code != 204 {
		t.Fatalf("rename: %d %v", r.code, r.body)
	}
	if r := e.do("DELETE", "/api/v1/auth/mfa/webauthn/keys/"+secondID, nil, full.cookie, csrfOf(full)); r.code != 204 {
		t.Fatalf("remove: %d %v", r.code, r.body)
	}
	e.handler.RequireMFA = func() bool { return true }
	if r := e.do("DELETE", "/api/v1/auth/mfa/webauthn/keys/"+firstID, nil, full.cookie, csrfOf(full)); r.code != 409 || r.body["code"] != "last_factor" {
		t.Fatalf("last factor: %d %v", r.code, r.body)
	}
	// Someone else's key is not there to remove.
	stranger := e.bareUser(t, "sol", user.RoleUser)
	sf := e.sessionFor(t, stranger, true)
	if r := e.do("DELETE", "/api/v1/auth/mfa/webauthn/keys/"+firstID, nil, sf.cookie, csrfOf(sf)); r.code != 403 {
		t.Fatalf("stranger without a step-up: %d %v", r.code, r.body)
	}
}

// TestAdministratorsMustUseTheirKey: with the setting on, an administrator
// who has a key no longer passes with the app's code; a recovery code still
// works, and a key does.
func TestAdministratorsMustUseTheirKey(t *testing.T) {
	e := newEnv(t)
	f := e.keysOn(t)
	u := e.bareUser(t, "ada", user.RoleAdmin)
	right, _ := enrol(t, e, u)
	full := e.sessionFor(t, u, true)
	if s := e.do("POST", "/api/v1/auth/mfa/step-up", map[string]string{"code": right()}, full.cookie, csrfOf(full)); s.code != 200 {
		t.Fatalf("step-up with the app: %d %v", s.code, s.body)
	}
	if c := e.addKey(t, full, newSoftKey(t), "Key"); c.code != 200 || c.body["recovery_codes"] != nil {
		t.Fatalf("key beside the app: %d %v", c.code, c.body)
	}
	f.KeyRequired = func(context.Context, string) (bool, error) { return true, nil }
	part := e.sessionFor(t, u, false)
	if r := e.verifyCode(part, right()); r.code != 403 || r.body["code"] != "key_required" {
		t.Fatalf("app code from an admin who must use a key: %d %v", r.code, r.body)
	}
	codes, err := f.NewRecoveryCodes(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r := e.verifyCode(part, codes[0]); r.code != 200 {
		t.Fatalf("recovery code: %d %v", r.code, r.body)
	}
}

// TestFactorsRecoveryCodesAndReset: recovery codes come with the first
// factor of either kind and stay when an app joins a key; a reset clears
// the app, the keys and the codes.
func TestFactorsRecoveryCodesAndReset(t *testing.T) {
	e := newEnv(t)
	f := e.keysOn(t)
	ctx := context.Background()
	u := e.bareUser(t, "ivy", user.RoleUser)
	c := e.addKey(t, e.sessionFor(t, u, true), newSoftKey(t), "Key")
	codes, _ := c.body["recovery_codes"].([]any)
	if c.code != 200 || len(codes) != recoveryCodeCount {
		t.Fatalf("register: %d %v", c.code, c.body)
	}
	// An app confirmed beside the key: Confirm makes no new codes.
	right, _ := enrol(t, e, u)
	if app, keys, err := f.Methods(ctx, u.ID); err != nil || !app || keys != 1 {
		t.Fatalf("methods: %v %d %v", app, keys, err)
	}
	if used, err := f.Verify(ctx, u.ID, right()); err != nil || used {
		t.Fatalf("app code: %v %v", used, err)
	}
	// The codes from the key still work after an app is confirmed beside it.
	if used, err := f.Verify(ctx, u.ID, codes[0].(string)); err != nil || !used {
		t.Fatalf("recovery code: %v %v", used, err)
	}
	if err := f.Reset(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.Keys.Count(ctx, u.ID); n != 0 {
		t.Fatalf("keys after a reset: %d", n)
	}
	if _, err := f.Verify(ctx, u.ID, codes[1].(string)); !errors.Is(err, ErrTOTPNotEnrolled) {
		t.Fatalf("after a reset: %v", err)
	}
}

// TestKeyStorage: a key's row round-trips on both databases, binary columns
// and flags included.
func TestKeyStorage(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		users := user.NewRepo(db)
		u := &user.User{Username: "row", DisplayName: "Row", Roles: []user.Role{user.RoleUser}}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		keys := NewKeys(db, testOrigin, "Zanskar Test")
		cred := &webauthn.Credential{ID: []byte{1, 2, 3, 0xff}, PublicKey: []byte{0xa5, 0x01}, AttestationType: "none"}
		cred.Authenticator.AAGUID = make([]byte, 16)
		cred.Authenticator.SignCount = 7
		cred.Flags.BackupEligible, cred.Flags.BackupState = true, true
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		k, err := keys.insert(ctx, tx, u.ID, "Phone", cred)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		creds, ids, err := keys.credentials(ctx, u.ID)
		if err != nil || len(creds) != 1 {
			t.Fatalf("credentials: %v %v", creds, err)
		}
		got := creds[0]
		if string(got.ID) != string(cred.ID) || got.Authenticator.SignCount != 7 || !got.Flags.BackupEligible || !got.Flags.BackupState || ids[string(cred.ID)] != k.ID {
			t.Fatalf("round trip: %+v", got)
		}
		list, err := keys.List(ctx, u.ID)
		if err != nil || len(list) != 1 || !list[0].Synced || list[0].Name != "Phone" || list[0].LastUsedAt != nil {
			t.Fatalf("list: %+v %v", list, err)
		}
		if err := keys.Rename(ctx, u.ID, k.ID, "Pixel"); err != nil {
			t.Fatal(err)
		}
		if err := keys.Rename(ctx, "someone-else", k.ID, "Mine"); !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("rename another's key: %v", err)
		}
		f := NewFactors(db, NewTOTP(db, nil, "Zanskar Test"), keys)
		if _, err := f.RemoveKey(ctx, u.ID, k.ID, true); !errors.Is(err, ErrLastFactor) {
			t.Fatalf("remove the last factor: %v", err)
		}
		if name, err := f.RemoveKey(ctx, u.ID, k.ID, false); err != nil || name != "Pixel" {
			t.Fatalf("remove: %q %v", name, err)
		}
	})
}
