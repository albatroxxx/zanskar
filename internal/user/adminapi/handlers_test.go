// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/user"
)

type fakeTOTP struct{ reset []string }

func (f *fakeTOTP) Reset(_ context.Context, id string) error {
	f.reset = append(f.reset, id)
	return nil
}

type env struct {
	db       *store.DB
	srv      http.Handler
	h        *AdminHandler
	users    *user.Repo
	sessions *auth.Sessions
	audit    *audit.Log
	totp     *fakeTOTP
	admin    *user.User
	cookie   *http.Cookie
	csrf     string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	db := storetest.Open(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := &env{db: db,
		users:    user.NewRepo(db),
		sessions: auth.NewSessions(db, bytes.Repeat([]byte{2}, 32), false),
		audit:    audit.NewLog(db),
		totp:     &fakeTOTP{},
	}
	h := &AdminHandler{Users: e.users, Sessions: e.sessions, TOTP: e.totp, Audit: e.audit, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: e.sessions, Users: e.users, Log: log}
	e.srv, e.h = mw.Authenticate(mw.CSRF(mux)), h

	e.admin = &user.User{Username: "root", DisplayName: "Root", Roles: []user.Role{user.RoleAdmin}}
	if err := e.users.Create(ctx, e.admin); err != nil {
		t.Fatal(err)
	}
	token, sess, err := e.sessions.Create(ctx, e.admin.ID, "127.0.0.1", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	e.cookie = &http.Cookie{Name: auth.CookieName, Value: token}
	e.csrf = e.sessions.CSRFToken(sess.ID)
	return e
}

type resp struct {
	code int
	body map[string]any
}

func (e *env) do(method, path string, body any) resp {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrf)
	req.RemoteAddr = "127.0.0.1:1"
	req.AddCookie(e.cookie)
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	out := resp{code: rr.Code}
	_ = json.Unmarshal(rr.Body.Bytes(), &out.body)
	return out
}

func TestCreateUserWithPassword(t *testing.T) {
	e := newEnv(t)
	r := e.do("POST", "/api/v1/users", map[string]any{
		"username": "Alice", "display_name": "Alice", "email": "Alice@Example.com",
		"roles": []string{"user", "auditor"}, "password": "a sufficiently long password",
	})
	if r.code != 201 {
		t.Fatalf("create: %d %v", r.code, r.body)
	}
	if _, ok := r.body["password_hash"]; ok {
		t.Fatal("password hash must not be serialised")
	}
	u, err := e.users.GetByUsername(context.Background(), "alice")
	if err != nil || !user.VerifyPassword(u.PasswordHash, "a sufficiently long password") {
		t.Fatalf("stored hash does not verify: %v", err)
	}
	if u.Email != "alice@example.com" {
		t.Fatalf("email not normalised: %q", u.Email)
	}
	events, _, _ := e.audit.List(context.Background(), audit.Filter{Action: "user.create"})
	if len(events) != 1 || !bytes.Contains(events[0].Details, []byte(`"roles_granted":["auditor"]`)) {
		t.Fatalf("expected user.create with roles_granted, got %s", events[0].Details)
	}
	if bytes.Contains(events[0].Details, []byte("sufficiently")) {
		t.Fatal("password leaked into audit details")
	}

	if r := e.do("POST", "/api/v1/users", map[string]any{"username": "alice", "display_name": "x", "roles": []string{"user"}}); r.code != 409 {
		t.Fatalf("duplicate: %d %v", r.code, r.body)
	}
	if r := e.do("POST", "/api/v1/users", map[string]any{"username": "bob", "display_name": "x", "roles": []string{"user"}, "password": "short"}); r.code != 400 {
		t.Fatalf("weak password: %d", r.code)
	}
	if r := e.do("POST", "/api/v1/users", map[string]any{"username": "bob", "display_name": "x", "roles": []string{}}); r.code != 400 {
		t.Fatalf("no roles: %d", r.code)
	}
	if r := e.do("POST", "/api/v1/users", map[string]any{"username": "bob", "display_name": "x", "roles": []string{"user"}, "extra": 1}); r.code != 400 {
		t.Fatalf("unknown field: %d", r.code)
	}
	if r := e.do("GET", "/api/v1/users?limit=1", nil); r.code != 200 || len(r.body["items"].([]any)) != 1 || r.body["next_cursor"] == nil {
		t.Fatalf("list: %d %v", r.code, r.body)
	}
}

func TestRolesAndLastAdmin(t *testing.T) {
	e := newEnv(t)
	if r := e.do("PUT", "/api/v1/users/"+e.admin.ID+"/roles", map[string]any{"roles": []string{"user"}}); r.code != 409 || r.body["code"] != "last_admin" {
		t.Fatalf("expected last_admin, got %d %v", r.code, r.body)
	}
	r := e.do("POST", "/api/v1/users", map[string]any{"username": "second", "display_name": "Second", "roles": []string{"user"}})
	id := r.body["id"].(string)
	r = e.do("PUT", "/api/v1/users/"+id+"/roles", map[string]any{"roles": []string{"user", "admin"}})
	if r.code != 200 {
		t.Fatalf("roles update: %d %v", r.code, r.body)
	}
	events, _, _ := e.audit.List(context.Background(), audit.Filter{Action: "user.roles.update"})
	if len(events) != 1 || !bytes.Contains(events[0].Details, []byte(`"roles_granted":["admin"]`)) || events[0].ActorUserID != e.admin.ID {
		t.Fatalf("roles update not audited correctly: %+v", events)
	}
	if r := e.do("GET", "/api/v1/users/nope", nil); r.code != 404 {
		t.Fatalf("404 expected, got %d", r.code)
	}
	if r := e.do("PUT", "/api/v1/users/"+e.admin.ID+"/roles", map[string]any{"roles": []string{"user"}}); r.code != 200 {
		t.Fatalf("demotion with another admin should pass: %d %v", r.code, r.body)
	}
	// Having demoted themselves, the caller is no longer an admin.
	if r := e.do("GET", "/api/v1/users", nil); r.code != 403 {
		t.Fatalf("expected 403 after self-demotion, got %d", r.code)
	}
}

func TestSelfProtectionAndDelete(t *testing.T) {
	e := newEnv(t)
	if r := e.do("DELETE", "/api/v1/users/"+e.admin.ID, nil); r.code != 409 || r.body["code"] != "self" {
		t.Fatalf("self delete: %d %v", r.code, r.body)
	}
	if r := e.do("PUT", "/api/v1/users/"+e.admin.ID, map[string]any{"status": "disabled"}); r.code != 409 || r.body["code"] != "self" {
		t.Fatalf("self disable: %d %v", r.code, r.body)
	}
	r := e.do("POST", "/api/v1/users", map[string]any{"username": "temp", "display_name": "Temp", "roles": []string{"user"}, "password": "temporary long password"})
	id := r.body["id"].(string)
	// The user has a live session; disabling revokes it.
	token, _, err := e.sessions.Create(context.Background(), id, "127.0.0.1", "x", true)
	if err != nil {
		t.Fatal(err)
	}
	if r := e.do("PUT", "/api/v1/users/"+id, map[string]any{"status": "disabled"}); r.code != 200 || r.body["status"] != "disabled" {
		t.Fatalf("disable: %d %v", r.code, r.body)
	}
	if _, err := e.sessions.Lookup(context.Background(), token); err == nil {
		t.Fatal("session should be revoked after disable")
	}
	if r := e.do("PUT", "/api/v1/users/"+id+"/password", map[string]any{"password": "another long password"}); r.code != 200 {
		t.Fatalf("password reset: %d %v", r.code, r.body)
	}
	if r := e.do("DELETE", "/api/v1/users/"+id+"/mfa", nil); r.code != 200 || len(e.totp.reset) != 1 {
		t.Fatalf("mfa reset: %d %v", r.code, r.body)
	}
	if r := e.do("DELETE", "/api/v1/users/"+id+"/sessions", nil); r.code != 200 {
		t.Fatalf("revoke sessions: %d", r.code)
	}
	if r := e.do("DELETE", "/api/v1/users/"+id, nil); r.code != 204 {
		t.Fatalf("delete: %d %v", r.code, r.body)
	}
	if r := e.do("GET", "/api/v1/users/"+id, nil); r.code != 404 {
		t.Fatalf("deleted user still readable: %d", r.code)
	}
	for _, action := range []string{"user.update", "user.password.reset", "user.mfa.reset", "user.sessions.revoke", "user.delete"} {
		if ev, _, _ := e.audit.List(context.Background(), audit.Filter{Action: action}); len(ev) == 0 {
			t.Errorf("missing audit event %s", action)
		}
	}
}

func TestNonAdminForbidden(t *testing.T) {
	e := newEnv(t)
	u := &user.User{Username: "plain", DisplayName: "Plain", Roles: []user.Role{user.RoleUser}}
	if err := e.users.Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	token, sess, _ := e.sessions.Create(context.Background(), u.ID, "127.0.0.1", "x", true)
	e.cookie = &http.Cookie{Name: auth.CookieName, Value: token}
	e.csrf = e.sessions.CSRFToken(sess.ID)
	if r := e.do("GET", "/api/v1/users", nil); r.code != 403 {
		t.Fatalf("expected 403, got %d", r.code)
	}
}

// TestOnboardingPasswords: creating a local user without a password
// returns a generated one-time password exactly once and marks the user as
// having to change it; an admin-set password does too; a password-less
// account gets neither; a reset can generate one as well.
func TestOnboardingPasswords(t *testing.T) {
	e := newEnv(t)
	r := e.do("POST", "/api/v1/users", map[string]any{"username": "newbie", "display_name": "New Person", "roles": []string{"user"}})
	if r.code != 201 {
		t.Fatalf("create: %d %v", r.code, r.body)
	}
	pw, _ := r.body["initial_password"].(string)
	if len(pw) != 20 || r.body["must_change_password"] != true {
		t.Fatalf("generated one-time password expected: %v", r.body)
	}
	if g := e.do("GET", "/api/v1/users/"+r.body["id"].(string), nil); g.body["initial_password"] != nil || g.body["must_change_password"] != true {
		t.Fatalf("the password is returned once only: %v", g.body)
	}
	r = e.do("POST", "/api/v1/users", map[string]any{"username": "chosen", "display_name": "Chosen", "roles": []string{"user"}, "password": "a long passphrase here"})
	if r.code != 201 || r.body["initial_password"] != nil || r.body["must_change_password"] != true {
		t.Fatalf("admin-set password: %d %v", r.code, r.body)
	}
	r = e.do("POST", "/api/v1/users", map[string]any{"username": "external", "display_name": "External", "roles": []string{"user"}, "password_less": true})
	if r.code != 201 || r.body["initial_password"] != nil || r.body["must_change_password"] != false {
		t.Fatalf("password-less: %d %v", r.code, r.body)
	}
	id := r.body["id"].(string)
	r = e.do("PUT", "/api/v1/users/"+id+"/password", map[string]any{"generate": true})
	if r.code != 200 || len(r.body["initial_password"].(string)) != 20 || r.body["must_change_password"] != true {
		t.Fatalf("generated reset: %d %v", r.code, r.body)
	}
	r = e.do("PUT", "/api/v1/users/"+id+"/password", map[string]any{"password": "another long passphrase", "must_change_password": false})
	if r.code != 200 || r.body["initial_password"] != nil || r.body["must_change_password"] != false {
		t.Fatalf("reset without change: %d %v", r.code, r.body)
	}
}

// TestResetMFA: an admin removes a user's authenticator (a lost phone) and
// every login session that passed the old second factor ends with it; the
// reset is audited. An unknown user is a 404 and resets nothing.
func TestResetMFA(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u := &user.User{Username: "ivy", DisplayName: "Ivy", Roles: []user.Role{user.RoleUser}}
	if err := e.users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, _, err := e.sessions.Create(ctx, u.ID, "203.0.113.8", "test", true); err != nil {
			t.Fatal(err)
		}
	}
	if r := e.do("DELETE", "/api/v1/users/no-such-user/mfa", nil); r.code != 404 || len(e.totp.reset) != 0 {
		t.Fatalf("unknown user: %d, resets %v", r.code, e.totp.reset)
	}
	r := e.do("DELETE", "/api/v1/users/"+u.ID+"/mfa", nil)
	if r.code != 200 || r.body["sessions_revoked"] != float64(2) {
		t.Fatalf("reset: %d %v", r.code, r.body)
	}
	if len(e.totp.reset) != 1 || e.totp.reset[0] != u.ID {
		t.Fatalf("authenticator reset for %v, want %s", e.totp.reset, u.ID)
	}
	evs, _, err := e.audit.List(ctx, audit.Filter{Action: "user.mfa.reset", Limit: 1})
	if err != nil || len(evs) != 1 || evs[0].ObjectID != u.ID || evs[0].ActorUserID != e.admin.ID {
		t.Fatalf("user.mfa.reset audit: %+v %v", evs, err)
	}
}

// TestUpdateKeepsWhatItIsNotGiven: PUT /users/{id} without an email cleared
// the stored one (B19), while a missing display name or status kept theirs,
// so a client changing only the status wiped the address; the console and
// the command line sent the email back to work around it. A field left out
// now keeps its value, and an empty email still clears it on purpose.
func TestUpdateKeepsWhatItIsNotGiven(t *testing.T) {
	e := newEnv(t)
	u := &user.User{Username: "vera", DisplayName: "Vera", Email: "vera@corp.example", Roles: []user.Role{user.RoleUser}}
	if err := e.users.Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	if r := e.do("PUT", "/api/v1/users/"+u.ID, map[string]any{"status": "disabled"}); r.code != 200 || r.body["email"] != "vera@corp.example" || r.body["display_name"] != "Vera" {
		t.Fatalf("a status change: %d %v, want the email and name kept", r.code, r.body)
	}
	if r := e.do("PUT", "/api/v1/users/"+u.ID, map[string]any{"email": ""}); r.code != 200 || r.body["email"] != nil && r.body["email"] != "" {
		t.Fatalf("an empty email: %d %v, want it cleared", r.code, r.body)
	}
	if r := e.do("PUT", "/api/v1/users/"+u.ID, map[string]any{"email": "vera@new.example"}); r.code != 200 || r.body["email"] != "vera@new.example" {
		t.Fatalf("a new email: %d %v", r.code, r.body)
	}
}

// TestCreateUserIntoGroups (2026-10-30): an account can be made a member of
// groups as it is created; a group that does not exist refuses the account
// too, naming the group.
func TestCreateUserIntoGroups(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	zero := store.TimeArg(store.NullTime{}.Time)
	if _, err := e.db.ExecContext(ctx, e.db.Rebind(`INSERT INTO groups (id, name, description, created_at, updated_at) VALUES (?, ?, '', ?, ?)`), "g-ops", "ops", zero, zero); err != nil {
		t.Fatal(err)
	}
	r := e.do("POST", "/api/v1/users", map[string]any{"username": "nia", "display_name": "Nia", "roles": []string{"user"}, "group_ids": []string{"g-ops", "g-gone"}})
	if r.code != 422 || r.body["code"] != "invalid_group" || !strings.Contains(fmt.Sprint(r.body["message"]), "g-gone") {
		t.Fatalf("unknown group: %d %v", r.code, r.body)
	}
	if _, err := e.users.GetByUsername(ctx, "nia"); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("a refused account was left behind: %v", err)
	}
	r = e.do("POST", "/api/v1/users", map[string]any{"username": "nia", "display_name": "Nia", "roles": []string{"user"}, "group_ids": []string{"g-ops"}})
	if r.code != 201 {
		t.Fatalf("create into a group: %d %v", r.code, r.body)
	}
	var n int
	if err := e.db.QueryRowContext(ctx, e.db.Rebind(`SELECT COUNT(*) FROM group_members WHERE group_id = ?`), "g-ops").Scan(&n); err != nil || n != 1 {
		t.Fatalf("membership: %d %v", n, err)
	}
}

// TestStatusOfAnAccountItsProviderTookAway (2026-10-31, the live 1.9.0
// report): a person deleted from Keycloak, their account disabled and marked
// by the sync, could be enabled again from the console, an active account
// for someone the directory no longer has. While the provider still lists
// or pushes its people the status is refused, a name or email edit stands,
// and an account disabled by hand stays the administrator's to toggle.
func TestStatusOfAnAccountItsProviderTookAway(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	idpID, now := store.NewID(), store.TimeArg(time.Now())
	if _, err := e.db.ExecContext(ctx, e.db.Rebind(`INSERT INTO identity_providers (id, name, type, config_enc, enabled, created_at, updated_at)
		VALUES (?, 'Keycloak', 'oidc', ?, TRUE, ?, ?)`), idpID, []byte{0}, now, now); err != nil {
		t.Fatal(err)
	}
	holds := true
	e.h.ProviderHolds = func(_ context.Context, id string) (string, bool, error) {
		if id != idpID {
			t.Errorf("asked about provider %q", id)
		}
		return "Keycloak", holds, nil
	}
	account := func(name string) *user.User {
		t.Helper()
		u := &user.User{Username: name, DisplayName: name, Roles: []user.Role{user.RoleUser}}
		if err := e.users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		if err := e.users.LinkExternal(ctx, u.ID, idpID, "ext-"+name); err != nil {
			t.Fatal(err)
		}
		return u
	}

	gone := account("gone")
	if ok, err := e.users.DisableRemoved(ctx, gone.ID, time.Now()); err != nil || !ok {
		t.Fatalf("disable as the sync does: %v %v", ok, err)
	}
	for _, status := range []string{"active", "locked"} {
		r := e.do("PUT", "/api/v1/users/"+gone.ID, map[string]any{"status": status})
		if r.code != http.StatusConflict || r.body["code"] != "left_provider" || r.body["message"] != "Keycloak no longer has this person; the account is enabled again when it does" {
			t.Fatalf("%s: %d %v", status, r.code, r.body)
		}
	}
	if r := e.do("PUT", "/api/v1/users/"+gone.ID, map[string]any{"display_name": "Gone Person"}); r.code != 200 || r.body["display_name"] != "Gone Person" || r.body["status"] != "disabled" {
		t.Fatalf("a name edit: %d %v", r.code, r.body)
	}
	if u, _ := e.users.GetByID(ctx, gone.ID); u.Status != user.StatusDisabled || u.DirectoryRemovedAt == nil {
		t.Fatalf("after the refusals: %s %v, want disabled and still marked", u.Status, u.DirectoryRemovedAt)
	}

	// Disabled and enabled by hand, as the report did before the sync could
	// apply the removal: the administrator's decision either way.
	byHand := account("byhand")
	for _, status := range []string{"disabled", "active"} {
		if r := e.do("PUT", "/api/v1/users/"+byHand.ID, map[string]any{"status": status}); r.code != 200 || r.body["status"] != status {
			t.Fatalf("by hand, %s: %d %v", status, r.code, r.body)
		}
	}

	// The provider no longer holds its people (sync and SCIM off, disabled,
	// or deleted): the account is the administrator's again.
	holds = false
	if r := e.do("PUT", "/api/v1/users/"+gone.ID, map[string]any{"status": "active"}); r.code != 200 || r.body["status"] != "active" {
		t.Fatalf("enable once the provider lets go: %d %v", r.code, r.body)
	}
	if u, _ := e.users.GetByID(ctx, gone.ID); u.DirectoryRemovedAt != nil {
		t.Fatal("the mark must go with an administrator's change of status")
	}
}
