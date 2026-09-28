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
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

type handlerEnv struct {
	srv   http.Handler
	db    *store.DB
	users *user.Repo
	admin *http.Cookie
	csrf  string
}

func newHandlerEnv(t *testing.T) *handlerEnv {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{3}, 32), false)

	h := &AdminHandler{Repo: NewRepo(db), Users: users, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	e := &handlerEnv{srv: mw.Authenticate(mw.CSRF(mux)), db: db, users: users}

	admin := &user.User{Username: "admin", DisplayName: "Admin", Roles: []user.Role{user.RoleAdmin}}
	if err := users.Create(ctx, admin); err != nil {
		t.Fatal(err)
	}
	tok, sess, err := sessions.Create(ctx, admin.ID, "127.0.0.1", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	e.admin = &http.Cookie{Name: auth.CookieName, Value: tok}
	e.csrf = sessions.CSRFToken(sess.ID)
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

func (e *handlerEnv) createUser(t *testing.T, name string, roles ...user.Role) *user.User {
	t.Helper()
	u := &user.User{Username: name, DisplayName: name, Roles: roles}
	if err := e.users.Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

// TestPolicySubjectMustBeAbleToConnect covers the review-only rule of ADR
// 0006 at the policy layer: a user-scoped policy cannot name an account that
// holds only auditor, because such an account is refused at connect time and
// the policy would only mislead. Granting the user role lifts the refusal, and
// group policies are not inspected.
func TestPolicySubjectMustBeAbleToConnect(t *testing.T) {
	e := newHandlerEnv(t)
	ctx := context.Background()
	reviewer := e.createUser(t, "reviewer", user.RoleAuditor)
	operator := e.createUser(t, "operator", user.RoleUser)

	body := func(userID string) map[string]any {
		return map[string]any{"name": "p-" + userID[:6], "user_id": userID,
			"target_selector": map[string]any{"tags": map[string]string{"env": "prod"}}, "protocols": []string{"ssh"}}
	}

	code, out := e.do("POST", "/api/v1/access-policies", body(reviewer.ID))
	if code != http.StatusUnprocessableEntity || out["code"] != "review_only_subject" {
		t.Fatalf("auditor-only subject: got %d %v, want 422 review_only_subject", code, out)
	}
	code, out = e.do("POST", "/api/v1/access-policies", body("00000000000000000000000000000000"))
	if code != http.StatusUnprocessableEntity || out["code"] != "invalid_subject" {
		t.Fatalf("unknown subject: got %d %v, want 422 invalid_subject", code, out)
	}
	code, out = e.do("POST", "/api/v1/access-policies", body(operator.ID))
	if code != http.StatusCreated {
		t.Fatalf("user subject: got %d %v, want 201", code, out)
	}
	policyID, _ := out["id"].(string)

	// Updating an existing policy onto a review-only subject is refused too.
	code, out = e.do("PUT", "/api/v1/access-policies/"+policyID, body(reviewer.ID))
	if code != http.StatusUnprocessableEntity || out["code"] != "review_only_subject" {
		t.Fatalf("update to auditor-only subject: got %d %v, want 422", code, out)
	}

	// Once the account can connect, the same policy is accepted.
	if err := e.users.SetRoles(ctx, reviewer.ID, []user.Role{user.RoleAuditor, user.RoleUser}); err != nil {
		t.Fatal(err)
	}
	if code, out = e.do("PUT", "/api/v1/access-policies/"+policyID, body(reviewer.ID)); code != http.StatusOK {
		t.Fatalf("update after granting user: got %d %v, want 200", code, out)
	}

	// Group subjects are not inspected: membership is checked at connect time.
	now := store.TimeArg(time.Now())
	if _, err := e.db.ExecContext(ctx, e.db.Rebind(`INSERT INTO groups (id, name, created_at, updated_at) VALUES ('g1', 'ops', ?, ?)`), now, now); err != nil {
		t.Fatal(err)
	}
	code, out = e.do("POST", "/api/v1/access-policies", map[string]any{"name": "grp", "group_id": "g1",
		"target_selector": map[string]any{"tags": map[string]string{"env": "prod"}}, "protocols": []string{"ssh"}})
	if code != http.StatusCreated {
		t.Fatalf("group policy: got %d %v, want 201", code, out)
	}
}
