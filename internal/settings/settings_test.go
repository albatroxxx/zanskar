// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

func newDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(context.Background(), config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestRepoAndValidate(t *testing.T) {
	ctx := context.Background()
	r := NewRepo(newDB(t))
	s, err := r.Get(ctx, KeyLoginBanner)
	if err != nil || s.Value != "" || s.UpdatedAt != nil {
		t.Fatalf("unset key must read empty: %+v %v", s, err)
	}
	if _, err := r.Set(ctx, KeyLoginBanner, "  Authorised use only.\r\nAll activity is recorded.  ", ""); err != nil {
		t.Fatal(err)
	}
	s, _ = r.Get(ctx, KeyLoginBanner)
	if s.Value != "Authorised use only.\nAll activity is recorded." || s.UpdatedAt == nil {
		t.Fatalf("normalised value: %+v", s)
	}
	if _, err := r.Set(ctx, KeyLoginBanner, strings.Repeat("x", MaxLoginBanner+1), ""); err == nil {
		t.Fatal("over-long banner must be refused")
	}
	if _, err := r.Set(ctx, "no_such_key", "x", ""); err == nil {
		t.Fatal("unknown key must be refused")
	}
	if _, err := r.Set(ctx, KeyLoginBanner, "", ""); err != nil {
		t.Fatal(err)
	}
	if s, _ = r.Get(ctx, KeyLoginBanner); s.Value != "" {
		t.Fatalf("clearing must store empty: %+v", s)
	}
}

// TestBannerRoutes: anyone reads the banner before sign-in, only an admin
// sets it, the change is audited with before and after, and the public
// shape carries the text alone.
func TestBannerRoutes(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{7}, 32), false)
	auditLog := audit.NewLog(db)
	h := &Handler{Repo: NewRepo(db), Audit: auditLog, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	srv := mw.Authenticate(mw.CSRF(mux))

	login := func(name string, role user.Role) (*http.Cookie, string) {
		u := &user.User{Username: name, DisplayName: name, Roles: []user.Role{role}}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		tok, sess, err := sessions.Create(ctx, u.ID, "203.0.113.9", "test", true)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: auth.CookieName, Value: tok}, sessions.CSRFToken(sess.ID)
	}
	admin, adminCSRF := login("root", user.RoleAdmin)
	plain, plainCSRF := login("alice", user.RoleUser)
	do := func(method, path string, body any, cookie *http.Cookie, csrf string) (int, map[string]any) {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		req.RemoteAddr = "203.0.113.9:4321"
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}

	if code, out := do("GET", "/api/v1/system/banner", nil, nil, ""); code != 200 || out["text"] != "" {
		t.Fatalf("public read before any banner: %d %v", code, out)
	}
	if code, _ := do("PUT", "/api/v1/admin/settings/login-banner", map[string]string{"value": "x"}, plain, plainCSRF); code != 403 {
		t.Fatalf("user must not set the banner: %d", code)
	}
	if code, _ := do("PUT", "/api/v1/admin/settings/login-banner", map[string]string{"value": "x"}, nil, ""); code != 401 && code != 403 {
		t.Fatalf("anonymous must not set the banner: %d", code)
	}
	code, out := do("PUT", "/api/v1/admin/settings/login-banner", map[string]string{"value": "This system is the property of Example Ltd.\nUse is monitored."}, admin, adminCSRF)
	if code != 200 || out["updated_by"] == nil {
		t.Fatalf("admin set: %d %v", code, out)
	}
	if code, out := do("PUT", "/api/v1/admin/settings/login-banner", map[string]string{"value": strings.Repeat("y", MaxLoginBanner+1)}, admin, adminCSRF); code != 400 {
		t.Fatalf("over-long banner: %d %v", code, out)
	}
	code, out = do("GET", "/api/v1/system/banner", nil, nil, "")
	if code != 200 || out["text"] != "This system is the property of Example Ltd.\nUse is monitored." || out["updated_by"] != nil {
		t.Fatalf("public read after set: %d %v", code, out)
	}
	events, _, err := auditLog.List(ctx, audit.Filter{Action: "settings.update"})
	if err != nil || len(events) != 1 {
		t.Fatalf("audit: %d %v", len(events), err)
	}
	var d map[string]any
	_ = json.Unmarshal(events[0].Details, &d)
	if d["before"] != "" || !strings.HasPrefix(d["after"].(string), "This system") || events[0].ObjectID != KeyLoginBanner {
		t.Fatalf("audit details: %v %+v", d, events[0])
	}
}
