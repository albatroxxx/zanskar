// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/user"
)

// fakeDirectory stands in for the LDAP providers: it knows one password per
// username and provisions the user on first sign-in, as the real one does.
type fakeDirectory struct {
	users     *user.Repo
	passwords map[string]string
	err       error // returned instead of a verdict, when set
	asked     int   // how many times the directory was consulted
}

func (d *fakeDirectory) Login(ctx context.Context, username, password, _ string) (*user.User, error) {
	d.asked++
	if d.err != nil {
		return nil, d.err
	}
	if pw, ok := d.passwords[username]; !ok || pw != password {
		return nil, ErrNoExternalIdentity
	}
	u, err := d.users.GetByUsername(ctx, username)
	if errors.Is(err, user.ErrNotFound) {
		u = &user.User{Username: username, DisplayName: username, Roles: []user.Role{user.RoleUser}}
		err = d.users.Create(ctx, u)
	}
	return u, err
}

func (e *env) lastLogin(t *testing.T) (audit.Event, map[string]any) {
	t.Helper()
	return e.lastEvent(t, "user.login")
}

// lastEvent returns the newest audit event for action and its details.
func (e *env) lastEvent(t *testing.T, action string) (audit.Event, map[string]any) {
	t.Helper()
	evs, _, err := e.audit.List(context.Background(), audit.Filter{Action: action, Limit: 1})
	if err != nil || len(evs) == 0 {
		t.Fatalf("no %s event: %v", action, err)
	}
	var d map[string]any
	_ = json.Unmarshal(evs[0].Details, &d)
	return evs[0], d
}

// enrol gives u a confirmed authenticator and pins the clock the TOTP
// checks read. right returns the code of the next 30-second step (each code
// works once); wrong returns one that matches no step the current window
// accepts.
func enrol(t *testing.T, e *env, u *user.User) (right, wrong func() string) {
	t.Helper()
	clock := time.Date(2026, 10, 11, 9, 0, 10, 0, time.UTC)
	e.totp.now = func() time.Time { return clock }
	enr, err := e.totp.Enroll(context.Background(), u.ID, u.Username)
	if err != nil {
		t.Fatal(err)
	}
	first, err := totp.GenerateCode(enr.Secret, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.totp.Confirm(context.Background(), u.ID, first); err != nil {
		t.Fatal(err)
	}
	right = func() string {
		clock = clock.Add(30 * time.Second)
		c, err := totp.GenerateCode(enr.Secret, clock)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	wrong = func() string { return wrongCode(t, enr.Secret, clock) }
	return right, wrong
}

// wrongCode returns a six-digit code that secret does not produce for the
// step at, or either step beside it.
func wrongCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	near := map[string]bool{}
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		c, err := totp.GenerateCode(secret, at.Add(d))
		if err != nil {
			t.Fatal(err)
		}
		near[c] = true
	}
	for _, c := range []string{"000000", "111111", "222222", "333333"} {
		if !near[c] {
			return c
		}
	}
	t.Fatal("no wrong code found")
	return ""
}

func csrfOf(r resp) map[string]string {
	return map[string]string{"X-CSRF-Token": r.body["csrf_token"].(string)}
}

func (e *env) verifyCode(r resp, code string) resp {
	return e.do("POST", "/api/v1/auth/mfa/totp/verify", map[string]string{"code": code}, r.cookie, csrfOf(r))
}

// TestWrongCodesShareTheAccountBudget: wrong second-factor codes count
// against the account with wrong passwords, across sign-ins: five lock it.
// The code that locks it ends its sign-in; a half-finished sign-in of a
// locked account is refused without comparing its code, the right one
// included, as a locked account's password is; and the next sign-in is
// refused as locked (M7).
func TestWrongCodesShareTheAccountBudget(t *testing.T) {
	e := newEnv(t)
	unlimited(e)
	const pw = "tess has a long passphrase"
	u := e.createUser(t, "tess", pw, user.RoleUser)
	right, wrong := enrol(t, e, u)

	a := login(e, "tess", pw)
	if a.body["status"] != "mfa_required" {
		t.Fatalf("sign-in: %d %v", a.code, a.body)
	}
	for i := 1; i <= 2; i++ {
		if v := e.verifyCode(a, wrong()); v.code != 401 || v.body["code"] != "invalid_code" {
			t.Fatalf("wrong code %d of the first sign-in: %d %v", i, v.code, v.body)
		}
	}
	b := login(e, "tess", pw)
	for i := 1; i <= 2; i++ {
		if v := e.verifyCode(b, wrong()); v.code != 401 || v.body["code"] != "invalid_code" {
			t.Fatalf("wrong code %d of the second sign-in: %d %v", i, v.code, v.body)
		}
	}
	if v := e.verifyCode(b, wrong()); v.code != 401 || v.body["code"] != "sign_in_ended" {
		t.Fatalf("the account's fifth wrong code, the third of its sign-in: %d %v; want 401 sign_in_ended", v.code, v.body)
	}
	if ev, d := e.lastEvent(t, "user.mfa.verify"); ev.Outcome != audit.Failure || d["locked_for"] == nil || d["session_ended"] != true {
		t.Fatalf("the locking code's audit: %v", d)
	}
	if got, err := e.users.GetByID(context.Background(), u.ID); err != nil || !got.IsLocked(time.Now()) {
		t.Fatalf("five wrong codes across two sign-ins must lock the account: %v", err)
	}
	if v := e.verifyCode(a, right()); v.code != 401 || v.body["code"] != "sign_in_ended" {
		t.Fatalf("the right code in a half-finished sign-in of the locked account: %d %v; want 401 sign_in_ended", v.code, v.body)
	}
	if _, d := e.lastEvent(t, "user.mfa.verify"); d["reason"] != "locked" {
		t.Fatalf("refused on a locked account, audit reason %v", d["reason"])
	}
	if r := login(e, "tess", pw); r.code != 401 {
		t.Fatalf("a password sign-in after five wrong codes: %d %v, want 401", r.code, r.body)
	}
	if _, d := e.lastLogin(t); d["reason"] != "locked" {
		t.Fatalf("refused sign-in audit reason %v, want locked", d["reason"])
	}
}

// TestOnlyACompleteSignInClearsTheCount: the right password with a second
// factor still owed leaves the account's failure count as it is; the right
// code completes the sign-in and clears it. With no second factor owed the
// password completes the sign-in and clears it at once (M7).
func TestOnlyACompleteSignInClearsTheCount(t *testing.T) {
	e := newEnv(t)
	unlimited(e)
	ctx := context.Background()
	failed := func(id string) int {
		t.Helper()
		got, err := e.users.GetByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return got.FailedLogins
	}
	const pw = "una has a long passphrase"
	u := e.createUser(t, "una", pw, user.RoleUser)
	right, wrong := enrol(t, e, u)
	login(e, "una", "not the password of una")
	r := login(e, "una", pw)
	if r.body["status"] != "mfa_required" {
		t.Fatalf("sign-in: %d %v", r.code, r.body)
	}
	if n := failed(u.ID); n != 1 {
		t.Fatalf("a wrong password, then the right one with the code still owed: %d failures on the account, want 1", n)
	}
	if v := e.verifyCode(r, wrong()); v.code != 401 {
		t.Fatalf("wrong code: %d %v", v.code, v.body)
	}
	if n := failed(u.ID); n != 2 {
		t.Fatalf("after a wrong code: %d failures, want 2", n)
	}
	if v := e.verifyCode(r, right()); v.code != 200 || v.body["status"] != "ok" {
		t.Fatalf("right code: %d %v", v.code, v.body)
	}
	if n := failed(u.ID); n != 0 {
		t.Fatalf("after the right code completed the sign-in: %d failures, want 0", n)
	}

	v := e.createUser(t, "vera", "vera has a long passphrase", user.RoleUser)
	if _, err := e.users.RecordLoginFailure(ctx, v.ID, e.handler.MaxFailures, e.handler.LockFor); err != nil {
		t.Fatal(err)
	}
	if r := login(e, "vera", "vera has a long passphrase"); r.body["status"] != "ok" {
		t.Fatalf("password-only sign-in: %d %v", r.code, r.body)
	}
	if n := failed(v.ID); n != 0 {
		t.Fatalf("after a complete password-only sign-in: %d failures, want 0", n)
	}
}

// TestWrongEnrolmentCodesCount: the code that confirms a new authenticator
// counts like any other. During a sign-in that owes enrolment, wrong ones
// count against the account, the one that locks it ends the sign-in, and a
// right one completes the sign-in and clears the count. A full session that
// enrols is not a sign-in: its wrong codes count, but it carries on (M6).
//
// The sessions are made directly, as a sign-in owing enrolment (or a full
// one) would leave them, to spare a password hash per sign-in.
func TestWrongEnrolmentCodesCount(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	account := func(id string) *user.User {
		t.Helper()
		got, err := e.users.GetByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	confirm := func(r resp, code string) resp {
		return e.do("POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": code}, r.cookie, csrfOf(r))
	}
	enrolFrom := func(r resp) string {
		t.Helper()
		enr := e.do("POST", "/api/v1/auth/mfa/totp/enroll", nil, r.cookie, csrfOf(r))
		if enr.code != 200 {
			t.Fatalf("enroll: %d %v", enr.code, enr.body)
		}
		return enr.body["secret"].(string)
	}

	wade := e.bareUser(t, "wade", user.RoleUser)
	r := e.sessionFor(t, wade, false)
	bad := wrongCode(t, enrolFrom(r), time.Now())
	for i := 1; i < e.handler.MaxFailures; i++ {
		if c := confirm(r, bad); c.code != 401 || c.body["code"] != "invalid_code" {
			t.Fatalf("wrong enrolment code %d: %d %v", i, c.code, c.body)
		}
	}
	if n := account(wade.ID).FailedLogins; n != e.handler.MaxFailures-1 {
		t.Fatalf("after %d wrong enrolment codes: %d failures on the account", e.handler.MaxFailures-1, n)
	}
	if c := confirm(r, bad); c.code != 401 || c.body["code"] != "sign_in_ended" {
		t.Fatalf("the wrong enrolment code that locks the account: %d %v; want 401 sign_in_ended", c.code, c.body)
	}
	if !account(wade.ID).IsLocked(time.Now()) {
		t.Fatal("five wrong enrolment codes must lock the account")
	}

	xena := e.bareUser(t, "xena", user.RoleUser)
	r = e.sessionFor(t, xena, false)
	secret := enrolFrom(r)
	for range 2 {
		confirm(r, wrongCode(t, secret, time.Now()))
	}
	if n := account(xena.ID).FailedLogins; n != 2 {
		t.Fatalf("after two wrong enrolment codes: %d failures, want 2", n)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if c := confirm(r, code); c.code != 200 {
		t.Fatalf("right enrolment code: %d %v", c.code, c.body)
	}
	if n := account(xena.ID).FailedLogins; n != 0 {
		t.Fatalf("after enrolment completed the sign-in: %d failures, want 0", n)
	}

	yann := e.bareUser(t, "yann", user.RoleUser)
	r = e.sessionFor(t, yann, true)
	secret = enrolFrom(r)
	for i := 1; i <= e.handler.MaxFailures; i++ {
		if c := confirm(r, wrongCode(t, secret, time.Now())); c.code != 401 || c.body["code"] != "invalid_code" {
			t.Fatalf("wrong enrolment code %d from a full session: %d %v; want invalid_code, the session carries on", i, c.code, c.body)
		}
	}
	if me := e.do("GET", "/api/v1/auth/me", nil, r.cookie, nil); me.code != 200 || me.body["user"] == nil {
		t.Fatalf("the full session after five wrong enrolment codes: %d %v", me.code, me.body)
	}
	if !account(yann.ID).IsLocked(time.Now()) {
		t.Fatal("five wrong enrolment codes from a full session still lock the account against new sign-ins")
	}
}

// TestCodesSentAtOnceShareTheBudget: codes sent all at once, from several
// half-finished sign-ins, are compared one at a time for the account, each
// after the failures before it are counted, so no more of them are compared
// than the account's budget allows (M7).
func TestCodesSentAtOnceShareTheBudget(t *testing.T) {
	e := newEnv(t)
	zora := e.bareUser(t, "zora", user.RoleUser)
	_, wrong := enrol(t, e, zora)
	code := wrong()
	var signIns []resp
	for range 4 {
		signIns = append(signIns, e.sessionFor(t, zora, false))
	}
	var wg sync.WaitGroup
	for _, r := range signIns {
		for j := 0; j < e.handler.MFAAttempts; j++ {
			wg.Go(func() {
				e.verifyCode(r, code)
			})
		}
	}
	wg.Wait()
	evs, _, err := e.audit.List(context.Background(), audit.Filter{Action: "user.mfa.verify", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	compared := 0
	for _, ev := range evs {
		var d map[string]any
		_ = json.Unmarshal(ev.Details, &d)
		if d["reason"] == "bad_code" {
			compared++
		}
	}
	if sent := len(signIns) * e.handler.MFAAttempts; compared != e.handler.MaxFailures {
		t.Fatalf("%d of %d codes sent at once were compared; want %d, the account's budget", compared, sent, e.handler.MaxFailures)
	}
}

// unlimited lifts the per-address sign-in limit for tests about something
// else, so how fast they run cannot turn a refusal into a 429.
func unlimited(e *env) { e.handler.loginLimiter = newIPLimiter(100000, 100000) }

func login(e *env, username, password string) resp {
	return e.do("POST", "/api/v1/auth/login", map[string]string{"username": username, "password": password}, nil, nil)
}

// TestLoginRefusalsLookAlike: an unknown user, a locked account and a wrong
// password get the same answer, so the sign-in page does not reveal which
// usernames exist; each is audited with its real reason. A missing or
// absurdly long password is a malformed request.
func TestLoginRefusalsLookAlike(t *testing.T) {
	e := newEnv(t)
	unlimited(e)
	e.createUser(t, "carol", "correct horse battery 9", user.RoleUser)

	wrong := login(e, "carol", "not the password at all")
	unknown := login(e, "mallory", "not the password at all")
	if wrong.code != 401 || unknown.code != 401 || fmt.Sprint(wrong.body) != fmt.Sprint(unknown.body) {
		t.Fatalf("wrong password %d %v vs unknown user %d %v: must be identical", wrong.code, wrong.body, unknown.code, unknown.body)
	}
	// The typed name is audited as a short hash, never as text: a password
	// typed into the username box must not sit in the chain for good (S1 L3).
	if ev, d := e.lastLogin(t); ev.Outcome != audit.Failure || d["reason"] != "unknown_user" || d["username_hash"] != usernameHash("Mallory") || d["username"] != nil {
		t.Fatalf("unknown user audit: %v", d)
	}

	for i := 0; i < e.handler.MaxFailures; i++ {
		login(e, "carol", "still not the password")
	}
	locked := login(e, "carol", "correct horse battery 9")
	if locked.code != 401 || fmt.Sprint(locked.body) != fmt.Sprint(wrong.body) {
		t.Fatalf("locked account with the right password: %d %v; must look like a wrong password", locked.code, locked.body)
	}
	if _, d := e.lastLogin(t); d["reason"] != "locked" {
		t.Fatalf("locked audit reason %v", d["reason"])
	}

	for _, body := range []map[string]string{{"username": "carol"}, {"username": " ", "password": "x"}, {"username": "carol", "password": strings.Repeat("x", user.MaxPasswordLen+1)}} {
		if r := e.do("POST", "/api/v1/auth/login", body, nil, nil); r.code != 400 {
			t.Errorf("malformed login %v: %d, want 400", body, r.code)
		}
	}
}

// TestLoginRateLimit: one address gets a burst of attempts and is then
// refused before any password is checked, and the refusal is audited.
func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t)
	// A small burst keeps the test fast: each refused attempt still runs a
	// full password hash. The production limiter is the same type.
	e.handler.loginLimiter = newIPLimiter(20, 3)
	limited := 0
	for i := 0; i < 10 && limited == 0; i++ {
		if r := login(e, "nobody", "guess"); r.code == 429 {
			limited = i
		}
	}
	if limited == 0 {
		t.Fatal("10 attempts from one address were never rate limited")
	}
	if _, d := e.lastLogin(t); d["reason"] != "rate_limited" {
		t.Fatalf("rate limit audit reason %v", d["reason"])
	}
}

// TestLoginLimiterKeysIPv6By64: an IPv6 client usually holds a whole /64 and
// can sign in from any address in it, so the sign-in limit counts the /64,
// not each address. IPv4 stays per address (M10). The attempts have no
// username: the limiter spends its token before the body is read, so an
// admitted attempt is a 400 and no password hash is spent on the test.
func TestLoginLimiterKeysIPv6By64(t *testing.T) {
	e := newEnv(t)
	e.handler.loginLimiter = newIPLimiter(20, 1)
	try := func(addr string) resp {
		return e.doFrom(addr, "POST", "/api/v1/auth/login", map[string]string{"username": "", "password": "a guess at it"}, nil, nil)
	}
	for _, c := range []struct {
		addr string
		want int
		why  string
	}{
		{"[2001:db8:1:2::1]:4444", 400, "the first address of a /64"},
		{"[2001:db8:1:2:ffff:ffff:ffff:fffe]:4444", 429, "another address in the same /64"},
		{"[2001:db8:1:3::1]:4444", 400, "an address in the next /64"},
		{"203.0.113.7:4444", 400, "an IPv4 address"},
		{"203.0.113.8:4444", 400, "the IPv4 address next to it"},
	} {
		if r := try(c.addr); r.code != c.want {
			t.Fatalf("%s (%s): %d %v, want %d", c.why, c.addr, r.code, r.body, c.want)
		}
	}
}

// TestPasswordHashingIsBounded: each password check takes 64 MiB and a core
// for about 100 ms, so the sign-in paths run only so many at once. A check
// that gets no slot within the wait is answered 503 busy, counts nothing and
// writes no audit row; once a slot is free, sign-in works again (M10).
func TestPasswordHashingIsBounded(t *testing.T) {
	e := newEnv(t)
	unlimited(e)
	saved := passwordHashing
	passwordHashing = newHashGate(1, 20*time.Millisecond)
	t.Cleanup(func() { passwordHashing = saved })
	const pw = "omar has a long passphrase"
	omar := e.createUser(t, "omar", pw, user.RoleUser)
	session := e.sessionFor(t, omar, true)
	events := func() int {
		t.Helper()
		evs, _, err := e.audit.List(context.Background(), audit.Filter{Limit: 500})
		if err != nil {
			t.Fatal(err)
		}
		return len(evs)
	}

	leave, ok := passwordHashing.enter(context.Background())
	if !ok {
		t.Fatal("the only slot should be free")
	}
	before := events()
	for _, c := range []struct {
		what string
		do   func() resp
	}{
		{"a sign-in", func() resp { return login(e, "omar", pw) }},
		{"a sign-in as an unknown user", func() resp { return login(e, "nobody", pw) }},
		{"a password change", func() resp {
			return e.do("POST", "/api/v1/auth/password", map[string]string{"current_password": pw, "new_password": "omar picks another phrase"}, session.cookie, csrfOf(session))
		}},
	} {
		if r := c.do(); r.code != 503 || r.body["code"] != "busy" {
			t.Fatalf("%s with every hashing slot taken: %d %v, want 503 busy", c.what, r.code, r.body)
		}
	}
	if after := events(); after != before {
		t.Fatalf("%d audit rows for attempts refused as busy, want none", after-before)
	}
	if got, err := e.users.GetByID(context.Background(), omar.ID); err != nil || got.FailedLogins != 0 {
		t.Fatalf("a busy refusal must count nothing against the account: %v", err)
	}
	leave()
	if r := login(e, "omar", pw); r.code != 200 {
		t.Fatalf("a sign-in once a slot is free: %d %v", r.code, r.body)
	}
}

// TestExternalLogin: a directory user signs in on first use and is
// provisioned; a provisioned user with no local password signs in through
// the directory; a wrong directory password, or a directory error, is the
// same refusal as any other.
func TestExternalLogin(t *testing.T) {
	e := newEnv(t)
	unlimited(e)
	dir := &fakeDirectory{users: e.users, passwords: map[string]string{"dana": "directory pass 1", "erin": "directory pass 2"}}
	e.handler.ExternalLogin = dir

	if r := login(e, "dana", "directory pass 1"); r.code != 200 || r.body["status"] != "ok" || r.cookie == nil {
		t.Fatalf("first directory sign-in: %d %v", r.code, r.body)
	}
	if _, err := e.users.GetByUsername(context.Background(), "dana"); err != nil {
		t.Fatalf("dana was not provisioned: %v", err)
	}

	erin := &user.User{Username: "erin", DisplayName: "Erin", Roles: []user.Role{user.RoleUser}} // no local password
	if err := e.users.Create(context.Background(), erin); err != nil {
		t.Fatal(err)
	}
	if r := login(e, "erin", "directory pass 2"); r.code != 200 || r.body["status"] != "ok" {
		t.Fatalf("provisioned user through the directory: %d %v", r.code, r.body)
	}
	if ev, d := e.lastLogin(t); ev.ActorUserID != erin.ID || d["stage"] != "complete" {
		t.Fatalf("directory sign-in audit: actor %s %v", ev.ActorUserID, d)
	}

	// A wrong directory password counts against the account like a wrong
	// local one, and is audited as what it was (S1 L2).
	if r := login(e, "erin", "wrong"); r.code != 401 {
		t.Fatalf("wrong directory password: %d", r.code)
	}
	if _, d := e.lastLogin(t); d["reason"] != "external_bad_credentials" {
		t.Fatalf("refusal reason %v", d["reason"])
	}
	if u, _ := e.users.GetByID(context.Background(), erin.ID); u.FailedLogins != 1 {
		t.Fatalf("a wrong directory password must count: %d", u.FailedLogins)
	}
	dir.err = errors.New("ldap: connection refused")
	if r := login(e, "erin", "directory pass 2"); r.code != 401 {
		t.Fatalf("directory down: %d, want the ordinary refusal", r.code)
	}
	if _, d := e.lastLogin(t); d["reason"] != "directory_unavailable" {
		t.Fatalf("directory down reason %v", d["reason"])
	}
	dir.err = nil
	// Enough wrong passwords lock the account; while it is locked the
	// directory is not asked, even with the right password, so the gateway
	// cannot be used to drive the directory's own lockout.
	for i := 1; i < e.handler.MaxFailures; i++ {
		login(e, "erin", "wrong")
	}
	if _, d := e.lastLogin(t); d["locked_for"] == nil {
		t.Fatalf("the locking attempt should say so: %v", d)
	}
	asked := dir.asked
	if r := login(e, "erin", "directory pass 2"); r.code != 401 {
		t.Fatalf("locked account with the right directory password: %d", r.code)
	}
	if _, d := e.lastLogin(t); d["reason"] != "locked" {
		t.Fatalf("locked reason %v", d["reason"])
	}
	if dir.asked != asked {
		t.Fatalf("the directory was asked while the account was locked")
	}
	if r := login(e, "frank", "anything"); r.code != 401 {
		t.Fatalf("unknown to everyone: %d", r.code)
	}
}

// TestLoginUpgradesWeakHash: a password stored under older, weaker argon2id
// parameters is re-hashed with the current ones at the next good sign-in.
func TestLoginUpgradesWeakHash(t *testing.T) {
	e := newEnv(t)
	unlimited(e)
	const pw = "an old but correct password"
	salt := []byte("0123456789abcdef")
	weak := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, 8*1024, 1, 1,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(argon2.IDKey([]byte(pw), salt, 1, 8*1024, 1, 32)))
	if !user.NeedsRehash(weak) {
		t.Fatal("the test hash must count as weak")
	}
	u := &user.User{Username: "gail", DisplayName: "Gail", Roles: []user.Role{user.RoleUser}, PasswordHash: weak}
	if err := e.users.Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	if r := login(e, "gail", pw); r.code != 200 {
		t.Fatalf("sign-in with the weak hash: %d %v", r.code, r.body)
	}
	got, err := e.users.GetByUsername(context.Background(), "gail")
	if err != nil || got.PasswordHash == weak || user.NeedsRehash(got.PasswordHash) || !user.VerifyPassword(got.PasswordHash, pw) {
		t.Fatalf("hash not upgraded: %v", err)
	}
}

// TestDeleteExpiredSessions: sessions that can never be used again (revoked,
// or expired more than a day ago) are removed; live ones stay.
func TestDeleteExpiredSessions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u := e.createUser(t, "hank", "a sufficiently long pw", user.RoleUser)
	_, live, err := e.sessions.Create(ctx, u.ID, "203.0.113.5", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	_, revoked, _ := e.sessions.Create(ctx, u.ID, "203.0.113.5", "test", true)
	if err := e.sessions.Revoke(ctx, revoked.ID); err != nil {
		t.Fatal(err)
	}
	n, err := e.sessions.DeleteExpired(ctx)
	if err != nil || n != 1 {
		t.Fatalf("deleted %d, %v; want the revoked session only", n, err)
	}
	e.sessions.now = func() time.Time { return time.Now().Add(e.sessions.AbsoluteTTL + 48*time.Hour) }
	if n, err := e.sessions.DeleteExpired(ctx); err != nil || n != 1 {
		t.Fatalf("after expiry deleted %d, %v; want the live session %s", n, err, live.ID)
	}
}

// TestRateLimitedSignInsAreAuditedOncePerRun: every refused attempt wrote a
// hash-chained audit row before the body was even read (L11), so a flood from
// one address grew the log without bound and queued every real event behind
// the writer's lock. A run of refusals from an address is recorded once; the
// next run, after the address got through again, is recorded again.
func TestRateLimitedSignInsAreAuditedOncePerRun(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	l := newIPLimiter(60, 1) // one attempt a second
	l.now = func() time.Time { return now }
	e.handler.loginLimiter = l
	// No username: an admitted attempt is a 400 before any hash is spent.
	try := func() int {
		return e.doFrom("203.0.113.9:4444", "POST", "/api/v1/auth/login", map[string]string{"username": "", "password": "a guess at it"}, nil, nil).code
	}
	refusals := func() int {
		t.Helper()
		evs, _, err := e.audit.List(context.Background(), audit.Filter{Action: audit.UserLogin, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, ev := range evs {
			var d map[string]any
			_ = json.Unmarshal(ev.Details, &d)
			if d["reason"] == "rate_limited" {
				n++
			}
		}
		return n
	}
	run := func(refused int) {
		t.Helper()
		if code := try(); code != http.StatusBadRequest {
			t.Fatalf("the first attempt of a run: %d, want it admitted", code)
		}
		for i := range refused {
			if code := try(); code != http.StatusTooManyRequests {
				t.Fatalf("attempt %d of a run: %d, want 429", i+2, code)
			}
		}
	}
	run(5)
	if n := refusals(); n != 1 {
		t.Fatalf("five refused attempts wrote %d audit rows, want 1", n)
	}
	now = now.Add(2 * time.Second)
	run(3)
	if n := refusals(); n != 2 {
		t.Fatalf("a second run of refusals: %d audit rows in all, want 2", n)
	}
}
