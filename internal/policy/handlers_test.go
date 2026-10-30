// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/user"
)

// fakeInventory knows a few targets by kind and one autoscaling group.
type fakeInventory struct{}

func (fakeInventory) TargetKind(_ context.Context, id string) (string, bool, error) {
	k, ok := map[string]string{"web-1": protocol.KindHost, "web-2": protocol.KindHost, "orders": protocol.KindDatabase, "wiki": protocol.KindApplication}[id]
	return k, ok, nil
}

func (fakeInventory) GroupExists(_ context.Context, id string) (bool, error) {
	return id == "fleet", nil
}

// recorder stands in for the gateway's revoker: it notes whom it was asked
// to re-check.
type recorder struct {
	gateway.Revoker // only Recheck is used here
	rechecked       [][]string
}

func (r *recorder) Recheck(_ context.Context, users []string) int {
	r.rechecked = append(r.rechecked, slices.Clone(users))
	return len(users)
}

type handlerEnv struct {
	srv   http.Handler
	db    *store.DB
	users *user.Repo
	audit *audit.Log
	rv    *recorder
	admin *http.Cookie
	csrf  string
	group string
	ann   *user.User
	ben   *user.User
}

func newHandlerEnv(t *testing.T) *handlerEnv {
	t.Helper()
	ctx := context.Background()
	db := storetest.Open(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{3}, 32), false)
	e := &handlerEnv{db: db, users: users, audit: audit.NewLog(db), rv: &recorder{}}
	h := &AdminHandler{Repo: NewRepo(db), Users: users, Inventory: fakeInventory{}, Revoker: e.rv, Audit: e.audit, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	e.srv = mw.Authenticate(mw.CSRF(mux))
	mk := func(name string, roles ...user.Role) *user.User {
		u := &user.User{Username: name, DisplayName: name, Roles: roles}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	admin := mk("admin", user.RoleAdmin)
	e.ann, e.ben = mk("ann", user.RoleUser), mk("ben", user.RoleUser)
	now := store.TimeArg(nowUTC())
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO groups (id, name, created_at, updated_at) VALUES ('g-ops', 'ops', ?, ?)`), now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO group_members (group_id, user_id, added_at) VALUES ('g-ops', ?, ?)`), e.ann.ID, now); err != nil {
		t.Fatal(err)
	}
	e.group = "g-ops"
	tok, sess, err := sessions.Create(ctx, admin.ID, "127.0.0.1", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	e.admin, e.csrf = &http.Cookie{Name: auth.CookieName, Value: tok}, sessions.CSRFToken(sess.ID)
	return e
}

func (e *handlerEnv) do(method, path string, body any) (int, map[string]any) {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrf)
	req.RemoteAddr = "203.0.113.7:1234"
	req.AddCookie(e.admin)
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func (e *handlerEnv) lastEvent(t *testing.T, action string) map[string]any {
	t.Helper()
	evs, _, err := e.audit.List(context.Background(), audit.Filter{Action: action, Limit: 1})
	if err != nil || len(evs) != 1 {
		t.Fatalf("no %s event: %v", action, err)
	}
	var d map[string]any
	_ = json.Unmarshal(evs[0].Details, &d)
	return d
}

// body is a valid new policy: ops on web-1 over ssh, standing.
func (e *handlerEnv) body() map[string]any {
	return map[string]any{
		"name":     "ops-web",
		"subjects": []map[string]string{{"kind": "group", "id": e.group}},
		"grants": []map[string]any{{
			"kind": "host", "targets": []map[string]any{{"id": "web-1", "protocols": []string{"ssh"}}},
		}},
	}
}

// TestPolicyAPI (ADR 0036): a policy is written and read in the new shape,
// with the defaults a grant leaves out; the audit event summarises it
// without anything secret; the people it covers are re-checked.
func TestPolicyAPI(t *testing.T) {
	e := newHandlerEnv(t)
	code, out := e.do("POST", "/api/v1/access-policies", e.body())
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, out)
	}
	id := out["id"].(string)
	grants := out["grants"].([]any)
	g := grants[0].(map[string]any)
	if g["id"] == "" || g["access"] != "standing" || g["sign_in"] != "target" || g["require_mfa"] != true || g["idle_timeout_minutes"] != float64(15) {
		t.Fatalf("defaults: %v", g)
	}
	d := e.lastEvent(t, audit.PolicyCreate)
	if d["name"] != "ops-web" || len(d["grants"].([]any)) != 1 {
		t.Fatalf("create event: %v", d)
	}
	if len(e.rv.rechecked) != 1 || !slices.Equal(e.rv.rechecked[0], []string{e.ann.ID}) {
		t.Fatalf("a new policy re-checked %v, want ann (it can tighten)", e.rv.rechecked)
	}

	// An edit keeps the grant by its id, moves the subject to ben, and
	// re-checks both: the one it left and the one it reached.
	edit := e.body()
	edit["subjects"] = []map[string]string{{"kind": "user", "id": e.ben.ID}}
	eg := edit["grants"].([]map[string]any)
	eg[0]["id"] = g["id"]
	eg[0]["allow_clipboard"] = true
	if code, out := e.do("PUT", "/api/v1/access-policies/"+id, edit); code != http.StatusOK || out["grants"].([]any)[0].(map[string]any)["id"] != g["id"] {
		t.Fatalf("update: %d %v", code, out)
	}
	if got := e.rv.rechecked[1]; !slices.Equal(sorted(got), sorted([]string{e.ann.ID, e.ben.ID})) {
		t.Fatalf("an edit re-checked %v, want ann and ben", got)
	}
	if code, out := e.do("GET", "/api/v1/access-policies/"+id, nil); code != http.StatusOK || out["subjects"].([]any)[0].(map[string]any)["kind"] != "user" {
		t.Fatalf("get: %d %v", code, out)
	}

	// A delete re-checks whom it covered, read before the delete.
	if code, _ := e.do("DELETE", "/api/v1/access-policies/"+id, nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if got := e.rv.rechecked[2]; !slices.Equal(got, []string{e.ben.ID}) {
		t.Fatalf("a delete re-checked %v, want ben", got)
	}
	if d := e.lastEvent(t, audit.PolicyDelete); d["live_sessions_ended"] != float64(1) {
		t.Fatalf("delete event: %v", d)
	}
}

func sorted(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// TestPolicyAPIRefusals: every refusal names what is wrong, and nothing is
// stored.
func TestPolicyAPIRefusals(t *testing.T) {
	e := newHandlerEnv(t)
	auditor := &user.User{Username: "aud", DisplayName: "aud", Roles: []user.Role{user.RoleAuditor}}
	if err := e.users.Create(context.Background(), auditor); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		edit   func(b map[string]any)
		status int
		code   string
		says   string
	}{
		{"the old shape", func(b map[string]any) { b["group_id"] = e.group }, 400, "legacy_policy_shape", "group_id is gone"},
		{"an old condition", func(b map[string]any) { b["require_approval"] = true }, 400, "legacy_policy_shape", "require_approval"},
		{"an unknown field", func(b map[string]any) { b["colour"] = "red" }, 400, "bad_request", "unknown field"},
		{"no subject", func(b map[string]any) { b["subjects"] = []any{} }, 400, "bad_request", "at least one group or user"},
		{"a review-only user", func(b map[string]any) {
			b["subjects"] = []map[string]string{{"kind": "user", "id": auditor.ID}}
		}, 422, "review_only_subject", "review-only"},
		{"a user that does not exist", func(b map[string]any) {
			b["subjects"] = []map[string]string{{"kind": "user", "id": "nobody"}}
		}, 422, "invalid_subject", "not found"},
		{"a target that does not exist", func(b map[string]any) {
			b["grants"].([]map[string]any)[0]["targets"] = []map[string]any{{"id": "gone", "protocols": []string{"ssh"}}}
		}, 422, "unknown_target", "gone is not a live host"},
		{"a database in a host grant", func(b map[string]any) {
			b["grants"].([]map[string]any)[0]["targets"] = []map[string]any{{"id": "orders", "protocols": []string{"ssh"}}}
		}, 422, "kind_mismatch", "orders is a database, not a host"},
		{"ssh on a database", func(b map[string]any) {
			b["grants"] = []map[string]any{{"kind": "database", "targets": []map[string]any{{"id": "orders", "protocols": []string{"ssh"}}}}}
		}, 400, "bad_request", `a database does not serve "ssh"`},
		{"a group that does not exist", func(b map[string]any) {
			b["grants"] = []map[string]any{{"kind": "autoscaling", "targets": []map[string]any{{"id": "no-fleet", "protocols": []string{"ssh"}}}}}
		}, 422, "unknown_target", "no-fleet is not a live autoscaling"},
		{"a grant id on a new policy", func(b map[string]any) { b["grants"].([]map[string]any)[0]["id"] = "g-123" }, 422, "unknown_grant", "carry no id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := e.body()
			c.edit(b)
			code, out := e.do("POST", "/api/v1/access-policies", b)
			if code != c.status || out["code"] != c.code || !strings.Contains(out["message"].(string), c.says) {
				t.Fatalf("got %d %v, want %d %s saying %q", code, out, c.status, c.code, c.says)
			}
		})
	}
	if code, out := e.do("GET", "/api/v1/access-policies", nil); code != 200 || len(out["items"].([]any)) != 0 {
		t.Fatalf("a refused policy was stored: %v", out)
	}

	// An edit may not bring a grant id of its own invention.
	code, out := e.do("POST", "/api/v1/access-policies", e.body())
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	b := e.body()
	b["grants"].([]map[string]any)[0]["id"] = "not-ours"
	if code, out := e.do("PUT", "/api/v1/access-policies/"+out["id"].(string), b); code != 422 || out["code"] != "unknown_grant" {
		t.Fatalf("a foreign grant id: %d %v", code, out)
	}
}

func nowUTC() time.Time { return time.Now().UTC() }
