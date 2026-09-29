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

// TestPrecedenceAndSubscribe: default, then environment, then console; a
// set tells subscribers at once; a reset falls back and tells them again;
// a fresh service sees what was stored.
func TestPrecedenceAndSubscribe(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	svc := NewService(NewRepo(db), map[string]string{KeyRequireMFA: "false"}, nil)
	if err := svc.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if v, _ := svc.Get(KeyLogLevel); v.Value != "info" || v.Source != SourceDefault {
		t.Fatalf("default: %+v", v)
	}
	if v, _ := svc.Get(KeyRequireMFA); v.Value != "false" || v.Source != SourceEnvironment || svc.Bool(KeyRequireMFA) {
		t.Fatalf("environment: %+v", v)
	}
	admin := &user.User{Username: "root", DisplayName: "root", Roles: []user.Role{user.RoleAdmin}}
	if err := user.NewRepo(db).Create(ctx, admin); err != nil {
		t.Fatal(err)
	}
	var seen []string
	svc.Subscribe(KeyRequireMFA, func(v string) { seen = append(seen, v) })
	if v, err := svc.Set(ctx, KeyRequireMFA, "yes", admin.ID); err != nil || v.Value != "true" || v.Source != SourceConsole || v.UpdatedBy != admin.ID {
		t.Fatalf("set: %+v %v", v, err)
	}
	if !svc.Bool(KeyRequireMFA) || len(seen) != 1 || seen[0] != "true" {
		t.Fatalf("subscriber after set: %v bool=%v", seen, svc.Bool(KeyRequireMFA))
	}
	again := NewService(NewRepo(db), map[string]string{KeyRequireMFA: "false"}, nil)
	if err := again.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if v, _ := again.Get(KeyRequireMFA); v.Value != "true" || v.Source != SourceConsole {
		t.Fatalf("reload: %+v", v)
	}
	if v, err := svc.Reset(ctx, KeyRequireMFA); err != nil || v.Value != "false" || v.Source != SourceEnvironment {
		t.Fatalf("reset: %+v %v", v, err)
	}
	if len(seen) != 2 || seen[1] != "false" {
		t.Fatalf("subscriber after reset: %v", seen)
	}
	if _, err := svc.Set(ctx, "no.such", "x", ""); err == nil {
		t.Fatal("unknown key must be refused")
	}
	if len(svc.All()) != len(Definitions) {
		t.Fatalf("All must cover every definition")
	}
}

func TestValidateTypes(t *testing.T) {
	cases := []struct {
		key, in, want string
		ok            bool
	}{
		{KeyRequireMFA, " TRUE ", "true", true},
		{KeyRequireMFA, "0", "false", true},
		{KeyRequireMFA, "maybe", "", false},
		{KeyLogLevel, "Warn", "warn", true},
		{KeyLogLevel, "verbose", "", false},
		{KeyGuacdAddr, "127.0.0.1:4822", "127.0.0.1:4822", true},
		{KeyGuacdAddr, "", "", true},
		{KeyGuacdAddr, "guacd", "", false},
		{KeyGuacdAddr, "guacd:99999", "", false},
		{KeyLoginBanner, "  a\r\nb  ", "a\nb", true},
		{KeyLoginBanner, strings.Repeat("x", MaxLoginBanner+1), "", false},
	}
	for _, c := range cases {
		d, _ := Lookup(c.key)
		got, err := Validate(d, c.in)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("Validate(%s, %q) = %q, %v; want %q ok=%v", c.key, c.in, got, err, c.want, c.ok)
		}
	}
}

type env struct {
	srv   http.Handler
	svc   *Service
	audit *audit.Log
	admin *http.Cookie
	aCSRF string
	plain *http.Cookie
	pCSRF string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	db := newDB(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{7}, 32), false)
	boot := []Boot{{Key: "listen_addr", Title: "Listen address", EnvVar: "ZANSKAR_LISTEN_ADDR", Value: "127.0.0.1:8443"}}
	e := &env{svc: NewService(NewRepo(db), map[string]string{KeyLogLevel: "warn"}, boot), audit: audit.NewLog(db)}
	if err := e.svc.Load(ctx); err != nil {
		t.Fatal(err)
	}
	h := &Handler{Service: e.svc, Audit: e.audit, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	e.srv = mw.Authenticate(mw.CSRF(mux))
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
	e.admin, e.aCSRF = login("root", user.RoleAdmin)
	e.plain, e.pCSRF = login("alice", user.RoleUser)
	return e
}

func (e *env) do(method, path string, body any, cookie *http.Cookie, csrf string) (int, map[string]any) {
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
	e.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

// TestRoutes covers the generic routes: the listing carries both sections
// with sources; a PUT applies live (a subscriber sees it) and is audited
// with before and after; a DELETE resets to the environment value; a boot
// key is refused with the reason; a user is refused; the login-banner alias
// and the public read still work.
func TestRoutes(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	code, out := e.do("GET", "/api/v1/admin/settings", nil, e.admin, e.aCSRF)
	if code != 200 {
		t.Fatalf("list: %d %v", code, out)
	}
	runtime, _ := out["runtime"].([]any)
	boot, _ := out["boot"].([]any)
	if len(runtime) != len(Definitions) || len(boot) != 1 {
		t.Fatalf("listing shape: %d runtime, %d boot", len(runtime), len(boot))
	}
	var level map[string]any
	for _, it := range runtime {
		m := it.(map[string]any)
		if m["key"] == KeyLogLevel {
			level = m
		}
	}
	if level["value"] != "warn" || level["source"] != SourceEnvironment || level["type"] != string(TypeEnum) {
		t.Fatalf("log level entry: %v", level)
	}

	var applied []string
	e.svc.Subscribe(KeyLogLevel, func(v string) { applied = append(applied, v) })
	if code, out := e.do("PUT", "/api/v1/admin/settings/"+KeyLogLevel, map[string]string{"value": "debug"}, e.plain, e.pCSRF); code != 403 {
		t.Fatalf("user must not set: %d %v", code, out)
	}
	code, out = e.do("PUT", "/api/v1/admin/settings/"+KeyLogLevel, map[string]string{"value": "debug"}, e.admin, e.aCSRF)
	if code != 200 || out["value"] != "debug" || out["source"] != SourceConsole || len(applied) != 1 || applied[0] != "debug" {
		t.Fatalf("set: %d %v applied=%v", code, out, applied)
	}
	if code, out := e.do("PUT", "/api/v1/admin/settings/"+KeyLogLevel, map[string]string{"value": "loud"}, e.admin, e.aCSRF); code != 400 {
		t.Fatalf("bad enum: %d %v", code, out)
	}
	if code, out := e.do("PUT", "/api/v1/admin/settings/listen_addr", map[string]string{"value": "0.0.0.0:443"}, e.admin, e.aCSRF); code != 409 || out["code"] != "boot_setting" {
		t.Fatalf("boot key: %d %v", code, out)
	}
	if code, out := e.do("PUT", "/api/v1/admin/settings/nope", map[string]string{"value": "x"}, e.admin, e.aCSRF); code != 404 {
		t.Fatalf("unknown key: %d %v", code, out)
	}
	code, out = e.do("DELETE", "/api/v1/admin/settings/"+KeyLogLevel, nil, e.admin, e.aCSRF)
	if code != 200 || out["value"] != "warn" || out["source"] != SourceEnvironment || len(applied) != 2 || applied[1] != "warn" {
		t.Fatalf("reset: %d %v applied=%v", code, out, applied)
	}

	// Banner alias and the public read.
	if code, out := e.do("PUT", "/api/v1/admin/settings/login-banner", map[string]string{"value": "Property of Example Ltd.\r\nUse is monitored."}, e.admin, e.aCSRF); code != 200 || out["value"] != "Property of Example Ltd.\nUse is monitored." {
		t.Fatalf("banner alias set: %d %v", code, out)
	}
	if code, out := e.do("GET", "/api/v1/admin/settings/login-banner", nil, e.admin, e.aCSRF); code != 200 || out["source"] != SourceConsole {
		t.Fatalf("banner alias get: %d %v", code, out)
	}
	if code, out := e.do("GET", "/api/v1/system/banner", nil, nil, ""); code != 200 || out["text"] != "Property of Example Ltd.\nUse is monitored." || out["updated_by"] != nil {
		t.Fatalf("public banner: %d %v", code, out)
	}

	events, _, err := e.audit.List(ctx, audit.Filter{ObjectType: "setting"})
	if err != nil || len(events) != 3 {
		t.Fatalf("audit: %d %v", len(events), err)
	}
	actions := map[string]int{}
	for _, ev := range events {
		actions[ev.Action]++
	}
	if actions["settings.update"] != 2 || actions["settings.reset"] != 1 {
		t.Fatalf("audit actions: %v", actions)
	}
}
