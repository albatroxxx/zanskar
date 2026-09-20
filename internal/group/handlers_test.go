// SPDX-License-Identifier: Apache-2.0

package group

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/user"
)

func TestGroupHandlers(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{3}, 32), false)
	auditLog := audit.NewLog(db)
	h := &AdminHandler{Groups: NewRepo(db), Audit: auditLog, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	srv := mw.Authenticate(mw.CSRF(mux))

	admin := &user.User{Username: "root", DisplayName: "Root", Roles: []user.Role{user.RoleAdmin}}
	if err := users.Create(ctx, admin); err != nil {
		t.Fatal(err)
	}
	token, sess, _ := sessions.Create(ctx, admin.ID, "127.0.0.1", "t", true)
	member := mkUser(t, users, "member")

	do := func(method, path string, body any) (int, map[string]any) {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", sessions.CSRFToken(sess.ID))
		req.RemoteAddr = "127.0.0.1:1"
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}

	code, body := do("POST", "/api/v1/groups", map[string]any{"name": "ops", "description": "operators"})
	if code != 201 || body["name"] != "ops" {
		t.Fatalf("create: %d %v", code, body)
	}
	id := body["id"].(string)
	if code, _ := do("POST", "/api/v1/groups", map[string]any{"name": "ops"}); code != 409 {
		t.Fatalf("duplicate: %d", code)
	}
	if code, body := do("GET", "/api/v1/groups", nil); code != 200 || len(body["items"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, body)
	}
	code, body = do("PUT", "/api/v1/groups/"+id+"/members", map[string]any{"user_ids": []string{member.ID}})
	if code != 200 || len(body["items"].([]any)) != 1 {
		t.Fatalf("set members: %d %v", code, body)
	}
	if code, _ := do("PUT", "/api/v1/groups/"+id+"/members", map[string]any{"user_ids": []string{"ghost"}}); code != 400 {
		t.Fatalf("unknown member: %d", code)
	}
	code, body = do("GET", "/api/v1/groups/"+id, nil)
	if code != 200 || body["member_count"].(float64) != 1 || len(body["members"].([]any)) != 1 {
		t.Fatalf("detail: %d %v", code, body)
	}
	if code, body := do("PUT", "/api/v1/groups/"+id, map[string]any{"name": "operations"}); code != 200 || body["name"] != "operations" {
		t.Fatalf("update: %d %v", code, body)
	}
	if code, _ := do("DELETE", "/api/v1/groups/"+id, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := do("GET", "/api/v1/groups/"+id, nil); code != 404 {
		t.Fatalf("after delete: %d", code)
	}
	for _, action := range []string{"group.create", "group.members.update", "group.update", "group.delete"} {
		ev, _, _ := auditLog.List(ctx, audit.Filter{Action: action})
		if len(ev) != 1 || ev[0].ActorUserID != admin.ID {
			t.Errorf("audit %s: %d events", action, len(ev))
		}
	}
	ev, _, _ := auditLog.List(ctx, audit.Filter{Action: "group.members.update"})
	if !bytes.Contains(ev[0].Details, []byte(member.ID)) {
		t.Fatalf("members audit should name the added id: %s", ev[0].Details)
	}
}
