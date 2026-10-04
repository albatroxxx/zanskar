// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

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
}

func (d *fakeDirectory) Login(ctx context.Context, username, password, _ string) (*user.User, error) {
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
	evs, _, err := e.audit.List(context.Background(), audit.Filter{Action: "user.login", Limit: 1})
	if err != nil || len(evs) == 0 {
		t.Fatalf("no user.login event: %v", err)
	}
	var d map[string]any
	_ = json.Unmarshal(evs[0].Details, &d)
	return evs[0], d
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
	if ev, d := e.lastLogin(t); ev.Outcome != audit.Failure || d["reason"] != "unknown_user" || d["username"] != "mallory" {
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

	if r := login(e, "erin", "wrong"); r.code != 401 {
		t.Fatalf("wrong directory password: %d", r.code)
	}
	if _, d := e.lastLogin(t); d["reason"] != "no_password_no_external" {
		t.Fatalf("refusal reason %v", d["reason"])
	}
	dir.err = errors.New("ldap: connection refused")
	if r := login(e, "erin", "directory pass 2"); r.code != 401 {
		t.Fatalf("directory down: %d, want the ordinary refusal", r.code)
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
