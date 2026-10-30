// SPDX-License-Identifier: Apache-2.0

package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/idp"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/user"
)

type revoked struct {
	gateway.Revoker // the rest are never called
	mu              sync.Mutex
	browser, live   []string
}

func (r *revoked) RevokeAllForUser(_ context.Context, id string) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.browser = append(r.browser, id)
	return 1, nil
}

func (r *revoked) UserRevoked(id string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.live = append(r.live, id)
	return 1
}

type env struct {
	srv   *httptest.Server
	repo  *idp.Repo
	users *user.Repo
	audit *audit.Log
	rev   *revoked
	p     *idp.Opened
	token string
	pv    *idp.Provisioner
}

func newEnv(t *testing.T, mutate func(*idp.Config)) *env {
	t.Helper()
	ctx := context.Background()
	db := storetest.Open(t)
	kek, _ := crypto.NewLocalKEK(bytes.Repeat([]byte{7}, 32))
	ring, err := keyring.Open(ctx, db, kek)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := &env{repo: idp.NewRepo(db, ring), users: user.NewRepo(db), audit: audit.NewLog(db), rev: &revoked{}}
	c := &idp.Config{OIDC: &idp.OIDCConfig{Issuer: "https://login.example.com", ClientID: "zanskar", ClientSecret: "s"},
		AutoProvision: true, SCIM: true, DefaultRoles: []user.Role{user.RoleUser}}
	if mutate != nil {
		mutate(c)
	}
	p := &idp.Provider{Name: "okta", Type: idp.TypeOIDC, Enabled: true}
	if err := e.repo.Create(ctx, p, c); err != nil {
		t.Fatal(err)
	}
	token, hash, err := idp.NewSCIMToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.repo.SetSCIMToken(ctx, p.ID, hash, p.CreatedAt); err != nil {
		t.Fatal(err)
	}
	e.token = token
	if e.p, err = e.repo.Open(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	e.pv = &idp.Provisioner{Users: e.users, Revoker: e.rev}
	h := &Handler{Providers: e.repo, Provisioner: e.pv, Audit: e.audit, Log: log,
		Lifecycle: &idp.Lifecycle{Users: e.users, Sessions: e.rev, Revoker: e.rev, Audit: e.audit, Log: log}}
	mux := http.NewServeMux()
	h.Register(mux)
	// The console's own chain, as the server mounts it: a server-to-server
	// SCIM call has no Origin and no cookie, and must pass it.
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{2}, 32), false)
	mw := &auth.Middleware{Sessions: sessions, Users: e.users, Log: log}
	e.srv = httptest.NewServer(mw.Authenticate(mw.CSRF(mux)))
	t.Cleanup(e.srv.Close)
	return e
}

// call sends one SCIM request with the provider's token (or token, when
// given) and returns the status and the decoded body.
func (e *env) call(t *testing.T, method, path string, body any, token ...string) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		raw, ok := body.(string)
		if !ok {
			b, _ := json.Marshal(body)
			raw = string(b)
		}
		rd = strings.NewReader(raw)
	}
	req, _ := http.NewRequest(method, e.srv.URL+"/api/v1/scim/"+e.p.ID+path, rd)
	tok := e.token
	if len(token) > 0 {
		tok = token[0]
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json; charset=utf-8")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	if res.StatusCode != http.StatusNoContent && !strings.HasPrefix(res.Header.Get("Content-Type"), "application/scim+json") {
		t.Fatalf("%s %s: content type %q", method, path, res.Header.Get("Content-Type"))
	}
	return res.StatusCode, out
}

func (e *env) account(t *testing.T, username string) *user.User {
	t.Helper()
	u, err := e.users.GetByUsername(context.Background(), username)
	if err != nil {
		t.Fatalf("%s: %v", username, err)
	}
	return u
}

func resources(out map[string]any) []any {
	list, _ := out["Resources"].([]any)
	return list
}

// TestOktaLifecycle follows the requests Okta's SCIM 2.0 guide documents:
// look the person up by userName, create them, read them back, update the
// profile with PUT, deactivate and reactivate with a path-less PATCH.
func TestOktaLifecycle(t *testing.T) {
	e := newEnv(t, nil)
	filter := "/Users?filter=" + url.QueryEscape(`userName eq "alice@corp.example"`) + "&startIndex=1&count=100"
	if st, out := e.call(t, "GET", filter, nil); st != 200 || out["totalResults"] != float64(0) {
		t.Fatalf("lookup before create: %d %v", st, out)
	}
	st, out := e.call(t, "POST", "/Users", map[string]any{
		"schemas": []string{schemaUser}, "userName": "Alice@Corp.example",
		"name":        map[string]string{"givenName": "Alice", "familyName": "Smith"},
		"emails":      []map[string]any{{"primary": true, "value": "alice@corp.example", "type": "work"}},
		"displayName": "Alice Smith", "locale": "en-US", "externalId": "00u1okta", "groups": []any{},
		"password": "never stored", "active": true,
	})
	if st != 201 || out["userName"] != "alice@corp.example" || out["active"] != true || out["externalId"] != "00u1okta" {
		t.Fatalf("create: %d %v", st, out)
	}
	id := out["id"].(string)
	alice := e.account(t, "alice@corp.example")
	if alice.ID != id || alice.IdPID != e.p.ID || alice.ExternalID != "" || alice.PasswordHash != "" || alice.DisplayName != "Alice Smith" || !alice.HasRole(user.RoleUser) {
		t.Fatalf("account: %+v", alice)
	}
	if st, out := e.call(t, "GET", filter, nil); st != 200 || out["totalResults"] != float64(1) || len(resources(out)) != 1 {
		t.Fatalf("lookup after create: %d %v", st, out)
	}
	if st, out := e.call(t, "GET", "/Users/"+id, nil); st != 200 || out["id"] != id {
		t.Fatalf("get: %d %v", st, out)
	}
	// Okta's profile push is a PUT of the whole user.
	st, out = e.call(t, "PUT", "/Users/"+id, map[string]any{
		"schemas": []string{schemaUser}, "id": id, "userName": "alice@corp.example",
		"name":   map[string]string{"givenName": "Alice", "familyName": "Liddell"},
		"emails": []map[string]any{{"primary": true, "value": "liddell@corp.example", "type": "work"}}, "active": true,
	})
	if st != 200 || out["displayName"] != "Alice Liddell" {
		t.Fatalf("put: %d %v", st, out)
	}
	if a := e.account(t, "alice@corp.example"); a.Email != "liddell@corp.example" {
		t.Fatalf("email after put: %q", a.Email)
	}
	// Deactivate.
	st, out = e.call(t, "PATCH", "/Users/"+id, map[string]any{"schemas": []string{schemaPatch},
		"Operations": []map[string]any{{"op": "replace", "value": map[string]any{"active": false}}}})
	if st != 200 || out["active"] != false {
		t.Fatalf("deactivate: %d %v", st, out)
	}
	if a := e.account(t, "alice@corp.example"); a.Status != user.StatusDisabled || a.DirectoryRemovedAt == nil {
		t.Fatalf("after deactivate: %s %v", a.Status, a.DirectoryRemovedAt)
	}
	if len(e.rev.browser) != 1 || len(e.rev.live) != 1 {
		t.Fatalf("sessions must end: %v %v", e.rev.browser, e.rev.live)
	}
	// Reactivate.
	if st, out := e.call(t, "PATCH", "/Users/"+id, map[string]any{"schemas": []string{schemaPatch},
		"Operations": []map[string]any{{"op": "replace", "value": map[string]any{"active": true}}}}); st != 200 || out["active"] != true {
		t.Fatalf("reactivate: %d %v", st, out)
	}
	evs, _, _ := e.audit.List(context.Background(), audit.Filter{ObjectID: id, Limit: 20})
	vias := map[string]int{}
	for _, ev := range evs {
		if strings.Contains(string(ev.Details), `"via":"scim"`) {
			vias[ev.Action]++
		}
		if strings.Contains(string(ev.Details), "never stored") {
			t.Fatal("a password the provider sent reached the audit log")
		}
	}
	if vias[audit.UserCreate] != 1 || vias[audit.UserUpdate] != 2 {
		t.Fatalf("audit: %v", vias)
	}
}

// TestEntraIDLifecycle follows the requests Microsoft documents for Entra
// ID's provisioning service: an enterprise-extension user, the capitalised
// ops and string booleans of its PATCH, dotted attribute paths, a filtered
// email path, a UPN change, then a delete, after which the account is not
// found, and a create of the same person again, which brings it back.
func TestEntraIDLifecycle(t *testing.T) {
	e := newEnv(t, nil)
	st, out := e.call(t, "POST", "/Users", `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
		"externalId": "0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef",
		"userName": "Test_User_ab6490ee-1e48-479e-a20b-2d77186b5dd1@testuser.com",
		"active": true,
		"emails": [{"primary": true, "type": "work", "value": "Test_User_fd0ea19b-0777-472c-9f96-4f70d2226f2e@testuser.com"}],
		"meta": {"resourceType": "User"},
		"name": {"formatted": "givenName familyName", "familyName": "familyName", "givenName": "givenName"},
		"roles": [],
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "Ops", "manager": {"value": "x"}}
	}`)
	if st != 201 {
		t.Fatalf("create: %d %v", st, out)
	}
	id := out["id"].(string)
	username := "test_user_ab6490ee-1e48-479e-a20b-2d77186b5dd1@testuser.com"
	if st, out := e.call(t, "GET", "/Users?filter="+url.QueryEscape(`externalId eq "0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef"`), nil); st != 200 || len(resources(out)) != 1 {
		t.Fatalf("by externalId: %d %v", st, out)
	}
	patch := func(ops string) (int, map[string]any) {
		return e.call(t, "PATCH", "/Users/"+id, `{"schemas":["`+schemaPatch+`"],"Operations":[`+ops+`]}`)
	}
	if st, out := patch(`{"op":"Replace","path":"active","value":"False"}`); st != 200 || out["active"] != false {
		t.Fatalf("deactivate: %d %v", st, out)
	}
	if st, out := patch(`{"op":"Replace","path":"active","value":"True"}`); st != 200 || out["active"] != true {
		t.Fatalf("reactivate: %d %v", st, out)
	}
	st, out = patch(`{"op":"Add","path":"name.givenName","value":"Grace"},{"op":"Add","path":"name.familyName","value":"Hopper"},` +
		`{"op":"Replace","path":"emails[type eq \"work\"].value","value":"grace@corp.example"},` +
		`{"op":"Add","path":"title","value":"Rear Admiral"},{"op":"Replace","value":{"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department":"Navy"}}`)
	if st != 200 || out["displayName"] != "Grace Hopper" {
		t.Fatalf("profile patch: %d %v", st, out)
	}
	if a := e.account(t, username); a.Email != "grace@corp.example" {
		t.Fatalf("email: %q", a.Email)
	}
	// A UPN change renames the account.
	if st, out := patch(`{"op":"Replace","path":"userName","value":"grace.hopper@corp.example"}`); st != 200 || out["userName"] != "grace.hopper@corp.example" {
		t.Fatalf("rename: %d %v", st, out)
	}
	// Delete: disabled, kept, and gone from SCIM's view.
	if st, _ := e.call(t, "DELETE", "/Users/"+id, nil); st != 204 {
		t.Fatalf("delete: %d", st)
	}
	if a := e.account(t, "grace.hopper@corp.example"); a.Status != user.StatusDisabled || a.SCIMDeletedAt == nil {
		t.Fatalf("after delete: %+v", a)
	}
	if st, _ := e.call(t, "GET", "/Users/"+id, nil); st != 404 {
		t.Fatalf("get after delete: %d", st)
	}
	if st, _ := e.call(t, "DELETE", "/Users/"+id, nil); st != 404 {
		t.Fatalf("delete twice: %d", st)
	}
	// Created again: the same account comes back, enabled.
	st, out = e.call(t, "POST", "/Users", map[string]any{"schemas": []string{schemaUser}, "userName": "grace.hopper@corp.example", "externalId": "0a21f0f2-new", "active": true})
	if st != 201 || out["id"] != id || out["active"] != true || out["externalId"] != "0a21f0f2-new" {
		t.Fatalf("rehire: %d %v", st, out)
	}
}

// TestCreateRules: a pre-created account with no password is taken over
// with its roles; a password account, another provider's account, or a
// second create of the same person is a uniqueness conflict; with account
// creation off a new person is refused; created inactive is disabled.
func TestCreateRules(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	pre := &user.User{Username: "pre@corp.example", DisplayName: "Pre", Roles: []user.Role{user.RoleAuditor}}
	if err := e.users.Create(ctx, pre); err != nil {
		t.Fatal(err)
	}
	local := &user.User{Username: "local", DisplayName: "Local", Roles: []user.Role{user.RoleUser}, PasswordHash: "$argon2id$x"}
	if err := e.users.Create(ctx, local); err != nil {
		t.Fatal(err)
	}
	st, out := e.call(t, "POST", "/Users", map[string]any{"userName": "pre@corp.example", "externalId": "p1"})
	if st != 201 || out["id"] != pre.ID {
		t.Fatalf("adopt: %d %v", st, out)
	}
	if a := e.account(t, "pre@corp.example"); a.IdPID != e.p.ID || !a.HasRole(user.RoleAuditor) || a.SCIMExternalID != "p1" {
		t.Fatalf("adopted: %+v", a)
	}
	for _, name := range []string{"local", "pre@corp.example"} {
		if st, out := e.call(t, "POST", "/Users", map[string]any{"userName": name}); st != 409 || out["scimType"] != "uniqueness" {
			t.Fatalf("%s: %d %v", name, st, out)
		}
	}
	if st, out := e.call(t, "POST", "/Users", map[string]any{"userName": "dup@corp.example", "emails": []map[string]any{{"value": "pre-mail@corp.example"}}}); st != 201 {
		t.Fatalf("dup setup: %d %v", st, out)
	}
	if st, out := e.call(t, "POST", "/Users", map[string]any{"userName": "dup2@corp.example", "emails": []map[string]any{{"value": "pre-mail@corp.example"}}}); st != 409 || out["scimType"] != "uniqueness" {
		t.Fatalf("duplicate email: %d %v", st, out)
	}
	if st, out := e.call(t, "POST", "/Users", map[string]any{"userName": "sleepy@corp.example", "active": false}); st != 201 || out["active"] != false {
		t.Fatalf("created inactive: %d %v", st, out)
	}
	for _, bad := range []map[string]any{{"userName": ""}, {"userName": "bad name"}, {"userName": "ok@corp.example", "active": "maybe"}} {
		if st, out := e.call(t, "POST", "/Users", bad); st != 400 || out["scimType"] != "invalidValue" {
			t.Fatalf("%v: %d %v", bad, st, out)
		}
	}
	e2 := newEnv(t, func(c *idp.Config) { c.AutoProvision = false })
	if st, _ := e2.call(t, "POST", "/Users", map[string]any{"userName": "new@corp.example"}); st != 403 {
		t.Fatalf("account creation off: %d", st)
	}
}

// TestSignInBindsTheProvisionedAccount: the first sign-in through the
// provider with the pushed username takes the account the push made, and
// from then on only that subject owns it.
func TestSignInBindsTheProvisionedAccount(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	st, out := e.call(t, "POST", "/Users", map[string]any{"userName": "kim@corp.example", "displayName": "Kim"})
	if st != 201 {
		t.Fatalf("create: %d", st)
	}
	res, err := e.pv.Resolve(ctx, e.p, idp.Identity{ExternalID: "sub-kim", Username: "kim@corp.example", DisplayName: "Kim"})
	if err != nil || !res.Linked || res.User.ID != out["id"] || res.User.ExternalID != "sub-kim" {
		t.Fatalf("first sign-in: %+v %v", res, err)
	}
	if _, err := e.pv.Resolve(ctx, e.p, idp.Identity{ExternalID: "sub-other", Username: "kim@corp.example"}); err == nil {
		t.Fatal("another subject must not take the account")
	}
	// A deactivated account cannot be signed in to before it is bound.
	_, out = e.call(t, "POST", "/Users", map[string]any{"userName": "off@corp.example", "active": false})
	if _, err := e.pv.Resolve(ctx, e.p, idp.Identity{ExternalID: "sub-off", Username: "off@corp.example"}); err == nil {
		t.Fatalf("a deactivated account must refuse the sign-in: %v", out)
	}
}

// TestLastAdministrator: the provider cannot deactivate or delete the last
// active administrator.
func TestLastAdministrator(t *testing.T) {
	e := newEnv(t, func(c *idp.Config) { c.DefaultRoles = []user.Role{user.RoleAdmin} })
	_, out := e.call(t, "POST", "/Users", map[string]any{"userName": "boss@corp.example"})
	id := out["id"].(string)
	if st, out := e.call(t, "PATCH", "/Users/"+id, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}}}); st != 409 || out["scimType"] != "mutability" {
		t.Fatalf("deactivate: %d %v", st, out)
	}
	if st, _ := e.call(t, "DELETE", "/Users/"+id, nil); st != 409 {
		t.Fatalf("delete: %d", st)
	}
	if a := e.account(t, "boss@corp.example"); a.Status != user.StatusActive {
		t.Fatal("the last admin was disabled")
	}
}

// TestGuard: no token, a wrong one, or another provider's is 401 and the
// first of a run is audited; past the burst it is 429; SCIM off or the
// provider disabled is 403; the token is never in the log.
func TestGuard(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	other := newEnv(t, nil)
	for _, tok := range []string{"", "zscim_wrong", other.token} {
		if st, out := e.call(t, "GET", "/Users", nil, tok); st != 401 || out["status"] != "401" {
			t.Fatalf("token %q: %d %v", tok, st, out)
		}
	}
	for range 20 {
		e.call(t, "GET", "/Users", nil, "zscim_wrong")
	}
	if st, _ := e.call(t, "GET", "/Users", nil, "zscim_wrong"); st != 429 {
		t.Fatalf("past the burst: %d", st)
	}
	if st, _ := e.call(t, "GET", "/Users", nil); st != 200 {
		t.Fatalf("the right token is never limited: %d", st)
	}
	evs, _, _ := e.audit.List(ctx, audit.Filter{Action: audit.IdPSCIM, Limit: 100})
	if len(evs) == 0 || len(evs) > 11 {
		t.Fatalf("refusals audited: %d", len(evs))
	}
	for _, ev := range evs {
		if strings.Contains(string(ev.Details), "zscim_") {
			t.Fatal("a token reached the audit log")
		}
	}
	// SCIM off, then the provider disabled.
	c := e.p.Config
	c.SCIM = false
	prov := e.p.Provider
	if err := e.repo.Update(ctx, &prov, &c); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.call(t, "GET", "/Users", nil); st != 403 {
		t.Fatalf("scim off: %d", st)
	}
	c.SCIM, prov.Enabled = true, false
	if err := e.repo.Update(ctx, &prov, &c); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.call(t, "GET", "/Users", nil); st != 403 {
		t.Fatalf("provider disabled: %d", st)
	}
	// Revoked.
	if err := e.repo.ClearSCIMToken(ctx, e.p.ID); err != nil {
		t.Fatal(err)
	}
	// The revoked token is a wrong one now: refused, as 429 here because
	// this address spent its burst above.
	if st, _ := e.call(t, "GET", "/Users", nil); st != 401 && st != 429 {
		t.Fatalf("revoked: %d", st)
	}
}

// TestDiscoveryAndRefusals: the discovery documents, groups refused as not
// provisioned, and requests a client may get wrong.
func TestDiscoveryAndRefusals(t *testing.T) {
	e := newEnv(t, nil)
	for _, path := range []string{"/ServiceProviderConfig", "/ResourceTypes", "/ResourceTypes/User", "/Schemas", "/Schemas/" + schemaUser} {
		if st, out := e.call(t, "GET", path, nil); st != 200 || out["schemas"] == nil {
			t.Fatalf("%s: %d %v", path, st, out)
		}
	}
	for _, path := range []string{"/ResourceTypes/Group", "/Schemas/urn:x"} {
		if st, _ := e.call(t, "GET", path, nil); st != 404 {
			t.Fatalf("%s: %d", path, st)
		}
	}
	if st, _ := e.call(t, "GET", "/Groups", nil); st != 501 {
		t.Fatalf("groups: %d", st)
	}
	if st, _ := e.call(t, "POST", "/Groups", map[string]any{"displayName": "ops"}); st != 501 {
		t.Fatalf("post groups: %d", st)
	}
	for _, f := range []string{`userName co "a"`, `emails[type eq "work"].value eq "a@b.c"`, `title eq "x"`, `userName eq "unterminated`} {
		if st, out := e.call(t, "GET", "/Users?filter="+url.QueryEscape(f), nil); st != 400 || out["scimType"] != "invalidFilter" {
			t.Fatalf("filter %q: %d %v", f, st, out)
		}
	}
	if st, _ := e.call(t, "POST", "/Users", "{not json"); st != 400 {
		t.Fatalf("bad json: %d", st)
	}
	if st, _ := e.call(t, "POST", "/Users", `{"userName":"`+strings.Repeat("a", bodyLimit)+`"}`); st != 413 {
		t.Fatalf("too large: %d", st)
	}
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/scim/"+e.p.ID+"/Users", strings.NewReader(`{"userName":"x1"}`))
	req.Header.Set("Authorization", "Bearer "+e.token)
	req.Header.Set("Content-Type", "text/plain")
	if res, err := http.DefaultClient.Do(req); err != nil || res.StatusCode != 415 {
		t.Fatalf("content type: %v %v", res, err)
	}
	if st, _ := e.call(t, "PATCH", "/Users/nope", map[string]any{"Operations": []any{}}); st != 404 {
		t.Fatalf("unknown id: %d", st)
	}
	_, out := e.call(t, "POST", "/Users", map[string]any{"userName": "pat@corp.example"})
	id := out["id"].(string)
	for _, bad := range []string{`{"Operations":[]}`, `{"Operations":[{"op":"move","path":"active","value":true}]}`, `{"Operations":[{"op":"remove","path":"userName"}]}`,
		`{"Operations":[{"op":"replace","value":"x"}]}`} {
		if st, _ := e.call(t, "PATCH", "/Users/"+id, bad); st != 400 {
			t.Fatalf("patch %s: %d", bad, st)
		}
	}
	// Paging.
	for _, n := range []string{"a1", "a2", "a3"} {
		e.call(t, "POST", "/Users", map[string]any{"userName": n + "@corp.example"})
	}
	if st, out := e.call(t, "GET", "/Users?startIndex=2&count=2", nil); st != 200 || out["totalResults"] != float64(4) || len(resources(out)) != 2 || out["startIndex"] != float64(2) {
		t.Fatalf("paging: %d %v", st, out)
	}
	// Accounts this provider does not provision are invisible to it.
	local := &user.User{Username: "local-only", DisplayName: "L", Roles: []user.Role{user.RoleUser}}
	if err := e.users.Create(context.Background(), local); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.call(t, "GET", "/Users/"+local.ID, nil); st != 404 {
		t.Fatalf("a local account: %d", st)
	}
}
