// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/user"
	"github.com/albatroxxx/zanskar/internal/version"
)

type hostEnv struct {
	t        *testing.T
	h        *Handler
	srv      http.Handler
	sessions *auth.Sessions
	auditLog *audit.Log
	ctrl     *Controller
	cookie   *http.Cookie
	csrf     string
	sessID   string

	mu   sync.Mutex
	runs [][]string
	fail error
}

// newHostEnv wires the lifecycle handler as a systemd host named gw-test,
// with a fake runner in place of systemctl and one signed-in administrator.
func newHostEnv(t *testing.T) *hostEnv { return newHostEnvUnder(t, "systemd") }

func newHostEnvUnder(t *testing.T, supervisor string) *hostEnv {
	t.Helper()
	ctx := context.Background()
	db := storetest.Open(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	e := &hostEnv{t: t, sessions: auth.NewSessions(db, bytes.Repeat([]byte{7}, 32), false), auditLog: audit.NewLog(db)}
	e.ctrl = &Controller{Registry: gateway.NewRegistry(), Log: log, Exit: func() {}, Poll: time.Millisecond}
	h := &Handler{
		Controller: e.ctrl, Audit: e.auditLog, Log: log, StartedAt: time.Now(),
		Supervisor: func() string { return supervisor },
		Hostname:   func() string { return "gw-test" },
		Run: func(_ context.Context, name string, args ...string) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.runs = append(e.runs, append([]string{name}, args...))
			return e.fail
		},
	}
	e.h = h
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: e.sessions, Users: users, Log: log}
	e.srv = mw.Authenticate(mw.CSRF(mux))
	u := &user.User{Username: "root", DisplayName: "root", Roles: []user.Role{user.RoleAdmin}}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	tok, sess, err := e.sessions.Create(ctx, u.ID, "203.0.113.9", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	e.cookie, e.csrf, e.sessID = &http.Cookie{Name: auth.CookieName, Value: tok}, e.sessions.CSRFToken(sess.ID), sess.ID
	return e
}

func (e *hostEnv) do(method, path string, body any) (int, map[string]any) {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrf)
	req.RemoteAddr = "203.0.113.9:4321"
	req.AddCookie(e.cookie)
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func (e *hostEnv) runsSeen() [][]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([][]string(nil), e.runs...)
}

func (e *hostEnv) waitFor(cond func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			e.t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (e *hostEnv) events(action string) []audit.Event {
	e.t.Helper()
	items, _, err := e.auditLog.List(context.Background(), audit.Filter{Action: action})
	if err != nil {
		e.t.Fatal(err)
	}
	return items
}

// TestHostActionGuards: the status says what the gear needs to know; a
// stale authenticator proof, a wrong hostname and a missing body are each
// refused before anything is audited or run.
func TestHostActionGuards(t *testing.T) {
	e := newHostEnv(t)
	code, out := e.do("GET", "/api/v1/admin/system/host", nil)
	if code != 200 || out["hostname"] != "gw-test" || out["available"] != true || out["mfa_fresh"] != false {
		t.Fatalf("host status: %d %v", code, out)
	}
	if code, out := e.do("POST", "/api/v1/admin/system/reboot", map[string]any{"confirm": "gw-test"}); code != 403 || out["code"] != "step_up_required" {
		t.Fatalf("stale proof: %d %v", code, out)
	}
	if err := e.sessions.MarkMFAProved(context.Background(), e.sessID); err != nil {
		t.Fatal(err)
	}
	if code, out := e.do("GET", "/api/v1/admin/system/host", nil); code != 200 || out["mfa_fresh"] != true {
		t.Fatalf("fresh proof: %d %v", code, out)
	}
	if code, out := e.do("POST", "/api/v1/admin/system/reboot", map[string]any{"confirm": "other-box"}); code != 400 || out["code"] != "confirm_mismatch" {
		t.Fatalf("wrong hostname: %d %v", code, out)
	}
	if code, out := e.do("POST", "/api/v1/admin/system/poweroff", map[string]any{"confirm": "gw-test", "wait_minutes": 999}); code != 400 {
		t.Fatalf("wait out of range: %d %v", code, out)
	}
	if len(e.runsSeen()) != 0 || len(e.events(audit.SystemReboot)) != 0 || len(e.events(audit.SystemPowerOff)) != 0 {
		t.Fatal("a refused action ran or was audited")
	}
}

// TestHostActionRuns: a reboot is audited before the drain and ends in
// `systemctl reboot` once the drain is done; a power-off the same way.
func TestHostActionRuns(t *testing.T) {
	e := newHostEnv(t)
	if err := e.sessions.MarkMFAProved(context.Background(), e.sessID); err != nil {
		t.Fatal(err)
	}
	code, out := e.do("POST", "/api/v1/admin/system/reboot", map[string]any{"confirm": "gw-test", "wait_minutes": 0})
	if code != 202 || out["draining"] != true {
		t.Fatalf("reboot: %d %v", code, out)
	}
	if evs := e.events(audit.SystemReboot); len(evs) != 1 || evs[0].Outcome != audit.Success {
		t.Fatalf("reboot audit: %+v", evs)
	}
	e.waitFor(func() bool { return len(e.runsSeen()) == 1 })
	if runs := e.runsSeen(); runs[0][0] != "systemctl" || runs[0][1] != "reboot" {
		t.Fatalf("ran %v", runs)
	}

	e2 := newHostEnv(t)
	if err := e2.sessions.MarkMFAProved(context.Background(), e2.sessID); err != nil {
		t.Fatal(err)
	}
	if code, _ := e2.do("POST", "/api/v1/admin/system/poweroff", map[string]any{"confirm": "gw-test", "wait_minutes": 0}); code != 202 {
		t.Fatalf("poweroff: %d", code)
	}
	e2.waitFor(func() bool { return len(e2.runsSeen()) == 1 })
	if runs := e2.runsSeen(); runs[0][1] != "poweroff" {
		t.Fatalf("ran %v", runs)
	}
}

// TestHostActionFailure: when systemctl is refused (no polkit rule), the
// failure is audited and the drain is cancelled so the gateway serves again.
func TestHostActionFailure(t *testing.T) {
	e := newHostEnv(t)
	e.fail = errors.New("systemctl reboot: exit status 1: Interactive authentication required")
	if err := e.sessions.MarkMFAProved(context.Background(), e.sessID); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.do("POST", "/api/v1/admin/system/reboot", map[string]any{"confirm": "gw-test", "wait_minutes": 0}); code != 202 {
		t.Fatalf("reboot: %d", code)
	}
	e.waitFor(func() bool { return !e.ctrl.Draining() })
	evs := e.events(audit.SystemReboot)
	if len(evs) != 2 || evs[0].Outcome != audit.Failure || evs[1].Outcome != audit.Success {
		t.Fatalf("audit after failure: %+v", evs)
	}
}

// TestHostActionUnsupported: off systemd the actions are refused with the
// reason, whatever the session proved, and nothing is audited or run.
func TestHostActionUnsupported(t *testing.T) {
	e := newHostEnvUnder(t, "kubernetes")
	if err := e.sessions.MarkMFAProved(context.Background(), e.sessID); err != nil {
		t.Fatal(err)
	}
	code, out := e.do("GET", "/api/v1/admin/system/host", nil)
	if code != 200 || out["available"] != false || out["reason"] == nil {
		t.Fatalf("host status: %d %v", code, out)
	}
	if code, out := e.do("POST", "/api/v1/admin/system/reboot", map[string]any{"confirm": "gw-test", "wait_minutes": 0}); code != 409 || out["code"] != "unsupported_supervisor" {
		t.Fatalf("reboot off systemd: %d %v", code, out)
	}
	if len(e.runsSeen()) != 0 || len(e.events(audit.SystemReboot)) != 0 {
		t.Fatal("a refused action ran or was audited")
	}
}

// TestInstallUpdate: the install is guarded like a reboot, refuses a version
// that is not newer, and — after the drain — writes the request file the
// package's path unit watches, atomically, naming the version and who asked.
func TestInstallUpdate(t *testing.T) {
	// A development build is never behind a release; the test runs as 1.0.0.
	was := version.Version
	version.Version = "1.0.0"
	t.Cleanup(func() { version.Version = was })
	e := newHostEnv(t)
	dir := t.TempDir()
	e.h.StateDir = dir
	if err := e.sessions.MarkMFAProved(context.Background(), e.sessID); err != nil {
		t.Fatal(err)
	}
	if code, out := e.do("POST", "/api/v1/admin/system/update/install", map[string]any{"version": "0.0.1", "confirm": "gw-test"}); code != 400 || out["code"] != "not_newer" {
		t.Fatalf("not newer: %d %v", code, out)
	}
	if code, out := e.do("POST", "/api/v1/admin/system/update/install", map[string]any{"version": "9.9.9", "confirm": "other"}); code != 400 || out["code"] != "confirm_mismatch" {
		t.Fatalf("wrong hostname: %d %v", code, out)
	}
	code, out := e.do("POST", "/api/v1/admin/system/update/install", map[string]any{"version": "v9.9.9", "confirm": "gw-test", "wait_minutes": 0})
	if code != 202 || out["draining"] != true {
		t.Fatalf("install: %d %v", code, out)
	}
	if evs := e.events(audit.SystemUpdate); len(evs) != 1 || evs[0].Outcome != audit.Success {
		t.Fatalf("install audit: %+v", evs)
	}
	path := filepath.Join(dir, UpdateRequestFile)
	e.waitFor(func() bool { _, err := os.Stat(path); return err == nil })
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var req updateRequest
	if err := json.Unmarshal(b, &req); err != nil || req.Version != "9.9.9" || req.RequestedBy == "" {
		t.Fatalf("request file: %s (%v)", b, err)
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Fatal("temp file left behind")
	}
	if len(e.runsSeen()) != 0 {
		t.Fatalf("an install ran a command: %v", e.runsSeen())
	}

	// Without a state directory the console cannot ask at all.
	e2 := newHostEnv(t)
	if err := e2.sessions.MarkMFAProved(context.Background(), e2.sessID); err != nil {
		t.Fatal(err)
	}
	if code, out := e2.do("POST", "/api/v1/admin/system/update/install", map[string]any{"version": "9.9.9", "confirm": "gw-test"}); code != 409 {
		t.Fatalf("no state dir: %d %v", code, out)
	}
}
