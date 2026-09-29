// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestParseEnvFile covers systemd's EnvironmentFile syntax: comments with #
// and ;, both quote styles, a continued line, a tolerated export prefix, and
// that non-ZANSKAR keys are dropped.
func TestParseEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env")
	content := strings.Join([]string{
		"# Zanskar environment",
		"; another comment style",
		"",
		"ZANSKAR_LISTEN_ADDR=127.0.0.1:8443",
		`ZANSKAR_DB_DSN="file:/var/lib/zanskar/zanskar.db?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"`,
		"ZANSKAR_ISSUER='Example Ltd'",
		"export ZANSKAR_LOG_LEVEL=info",
		"ZANSKAR_TRUSTED_PROXIES=127.0.0.1/32,\\",
		"::1/128",
		"PATH=/usr/bin",
		"ZANSKAR_MASTER_KEY=abc123",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ParseEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"ZANSKAR_LISTEN_ADDR":     "127.0.0.1:8443",
		"ZANSKAR_DB_DSN":          "file:/var/lib/zanskar/zanskar.db?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)",
		"ZANSKAR_ISSUER":          "Example Ltd",
		"ZANSKAR_LOG_LEVEL":       "info",
		"ZANSKAR_TRUSTED_PROXIES": "127.0.0.1/32,::1/128",
		"ZANSKAR_MASTER_KEY":      "abc123",
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

// TestDriftNamesButNeverValues: added, removed and modified variables are
// reported by name, sorted; the report and its JSON carry no value; the
// file states for missing and unchanged are distinct; the cache refreshes
// when the file is rewritten.
func TestDriftNamesButNeverValues(t *testing.T) {
	const secret = "s3cret-master-key"
	dir := t.TempDir()
	path := filepath.Join(dir, "env")
	write := func(lines ...string) {
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Make the change visible even on coarse mtime filesystems.
		future := time.Now().Add(2 * time.Second)
		_ = os.Chtimes(path, future, future)
	}
	started := map[string]string{"ZANSKAR_LISTEN_ADDR": "127.0.0.1:8443", "ZANSKAR_MASTER_KEY": secret, "ZANSKAR_LOG_LEVEL": "info"}
	d := &Drift{Path: path, Started: started}
	if r := d.Check(); r.State != FileMissing || r.RestartRequired() {
		t.Fatalf("missing file: %+v", r)
	}
	write("ZANSKAR_LISTEN_ADDR=127.0.0.1:8443", "ZANSKAR_MASTER_KEY="+secret, "ZANSKAR_LOG_LEVEL=info")
	if r := d.Check(); r.State != FileUnchanged || len(r.Changed) != 0 {
		t.Fatalf("unchanged: %+v", r)
	}
	write("ZANSKAR_LISTEN_ADDR=0.0.0.0:8443", "ZANSKAR_MASTER_KEY=other-"+secret, "ZANSKAR_GUACD_ADDR=127.0.0.1:4822")
	r := d.Check()
	if !r.RestartRequired() || strings.Join(r.Changed, ",") != "ZANSKAR_GUACD_ADDR,ZANSKAR_LISTEN_ADDR,ZANSKAR_LOG_LEVEL,ZANSKAR_MASTER_KEY" {
		t.Fatalf("changed: %+v", r)
	}
	js, _ := json.Marshal(r)
	if strings.Contains(string(js), secret) || strings.Contains(string(js), "0.0.0.0") {
		t.Fatalf("report leaks a value: %s", js)
	}
	if r2 := d.Check(); r2.State != FileChanged || len(r2.Changed) != 4 {
		t.Fatalf("cached: %+v", r2)
	}
	if r := (&Drift{}).Check(); r.State != FileNone {
		t.Fatalf("no path: %+v", r)
	}
}

// TestControllerDrain: with a wait, the restart happens once the last live
// session ends; with none, live sessions are ended with the restart cause
// and the exit follows; a cancel stops a pending drain.
func TestControllerDrain(t *testing.T) {
	reg := gateway.NewRegistry()
	var exits atomic.Int32
	c := &Controller{Registry: reg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Exit: func() { exits.Add(1) }, Poll: 10 * time.Millisecond}

	ctx := reg.Add(context.Background(), gateway.Live{SessionID: "s1", Protocol: "ssh"})
	d := c.Restart("admin", time.Minute)
	if !c.Draining() || d.WaitMinutes != 1 {
		t.Fatalf("drain not recorded: %+v", d)
	}
	time.Sleep(50 * time.Millisecond)
	if exits.Load() != 0 || ctx.Err() != nil {
		t.Fatal("exited while a session was live and the deadline was ahead")
	}
	reg.Remove("s1")
	waitFor(t, func() bool { return exits.Load() == 1 })

	// Immediate: the live session is ended with the restart cause.
	c2 := &Controller{Registry: reg, Exit: func() { exits.Add(1) }, Poll: 10 * time.Millisecond}
	ctx2 := reg.Add(context.Background(), gateway.Live{SessionID: "s2", Protocol: "rdp"})
	c2.Restart("admin", 0)
	waitFor(t, func() bool { return exits.Load() == 2 })
	if reason, _ := gateway.CancelReason(ctx2); reason != "gateway_restart" {
		t.Fatalf("session ended with reason %q", reason)
	}
	reg.Remove("s2")

	// Cancel.
	c3 := &Controller{Registry: reg, Exit: func() { exits.Add(1) }, Poll: 10 * time.Millisecond}
	reg.Add(context.Background(), gateway.Live{SessionID: "s3", Protocol: "ssh"})
	c3.Restart("admin", time.Minute)
	if !c3.Cancel() || c3.Draining() || c3.Cancel() {
		t.Fatal("cancel bookkeeping")
	}
	reg.Remove("s3")
	time.Sleep(50 * time.Millisecond)
	if exits.Load() != 2 {
		t.Fatal("a cancelled drain must not exit")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestRoutes: the status carries the file report and live count; a restart
// is accepted, audited with the changed names and not the values, and shows
// as draining; a cancel is audited; a second cancel is a 409; a user is
// refused.
func TestRoutes(t *testing.T) {
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
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{9}, 32), false)
	auditLog := audit.NewLog(db)
	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte("ZANSKAR_LISTEN_ADDR=0.0.0.0:443\nZANSKAR_MASTER_KEY=new-secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := gateway.NewRegistry()
	reg.Add(ctx, gateway.Live{SessionID: "live1", Protocol: "ssh"})
	ctrl := &Controller{Registry: reg, Log: log, Exit: func() {}, Poll: time.Hour}
	h := &Handler{Drift: &Drift{Path: path, Started: map[string]string{"ZANSKAR_LISTEN_ADDR": "127.0.0.1:8443", "ZANSKAR_MASTER_KEY": "old-secret-value"}},
		Controller: ctrl, Audit: auditLog, Log: log, StartedAt: time.Now().Add(-time.Hour)}
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
	admin, aCSRF := login("root", user.RoleAdmin)
	plain, pCSRF := login("alice", user.RoleUser)
	do := func(method, path string, body any, cookie *http.Cookie, csrf string) (int, map[string]any, string) {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.RemoteAddr = "203.0.113.9:4321"
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out, rr.Body.String()
	}

	code, out, raw := do("GET", "/api/v1/admin/system/status", nil, admin, aCSRF)
	if code != 200 || out["restart_required"] != true || out["live_sessions"] != float64(1) || out["draining"] != false {
		t.Fatalf("status: %d %v", code, out)
	}
	env := out["env_file"].(map[string]any)
	if env["state"] != FileChanged || len(env["changed"].([]any)) != 2 || strings.Contains(raw, "secret-value") {
		t.Fatalf("env report: %v", env)
	}
	if code, _, _ := do("GET", "/api/v1/admin/system/status", nil, plain, pCSRF); code != 403 {
		t.Fatalf("user status: %d", code)
	}
	if code, _, _ := do("POST", "/api/v1/admin/system/restart", map[string]int{"wait_minutes": 30}, plain, pCSRF); code != 403 {
		t.Fatalf("user restart: %d", code)
	}
	if code, out, _ := do("POST", "/api/v1/admin/system/restart", map[string]int{"wait_minutes": 999}, admin, aCSRF); code != 400 {
		t.Fatalf("bad wait: %d %v", code, out)
	}
	code, out, _ = do("POST", "/api/v1/admin/system/restart", map[string]int{"wait_minutes": 30}, admin, aCSRF)
	if code != 202 || out["draining"] != true || out["drain"].(map[string]any)["wait_minutes"] != float64(30) {
		t.Fatalf("restart: %d %v", code, out)
	}
	if !ctrl.Draining() {
		t.Fatal("controller not draining")
	}
	if code, out, _ := do("DELETE", "/api/v1/admin/system/restart", nil, admin, aCSRF); code != 200 || out["draining"] != false {
		t.Fatalf("cancel: %d %v", code, out)
	}
	if code, _, _ := do("DELETE", "/api/v1/admin/system/restart", nil, admin, aCSRF); code != 409 {
		t.Fatalf("second cancel: %d", code)
	}
	events, _, err := auditLog.List(ctx, audit.Filter{ObjectType: "system"})
	if err != nil || len(events) != 2 {
		t.Fatalf("audit: %d %v", len(events), err)
	}
	for _, ev := range events {
		js, _ := json.Marshal(ev.Details)
		if strings.Contains(string(js), "secret-value") {
			t.Fatalf("audit leaks a value: %s", js)
		}
		if ev.Action == "system.restart" && !strings.Contains(string(js), "ZANSKAR_MASTER_KEY") {
			t.Fatalf("restart audit lacks the changed names: %s", js)
		}
	}
}
