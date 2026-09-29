// SPDX-License-Identifier: Apache-2.0

package logring

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

// TestRing: records still reach the real handler; the ring keeps the last
// N newest first; level and text filters apply; WithAttrs and WithGroup
// attributes travel into the ring's copy.
func TestRing(t *testing.T) {
	var out bytes.Buffer
	ring := New(3)
	level := new(slog.LevelVar)
	log := slog.New(ring.Wrap(slog.NewJSONHandler(&out, &slog.HandlerOptions{Level: level})))
	log.Info("one", "n", 1)
	log.Warn("two", "n", 2)
	log.Debug("hidden")
	log.With("component", "sshgw").WithGroup("session").Error("three", "id", "abc")
	log.Info("four")
	if got := strings.Count(out.String(), "\n"); got != 4 {
		t.Fatalf("stderr must still get every enabled record, got %d lines", got)
	}
	snap := ring.Snapshot(slog.LevelDebug, "", 10)
	if len(snap) != 3 || snap[0].Msg != "four" || snap[1].Msg != "three" || snap[2].Msg != "two" {
		t.Fatalf("ring order/capacity: %+v", snap)
	}
	if snap[1].Attrs["component"] != "sshgw" || snap[1].Attrs["session.id"] != "abc" || snap[1].Level != "ERROR" {
		t.Fatalf("attrs: %+v", snap[1])
	}
	if got := ring.Snapshot(slog.LevelWarn, "", 10); len(got) != 2 {
		t.Fatalf("level filter: %+v", got)
	}
	if got := ring.Snapshot(slog.LevelDebug, "sshgw", 10); len(got) != 1 || got[0].Msg != "three" {
		t.Fatalf("text filter on attrs: %+v", got)
	}
	if ring.Seen() != 4 || ring.Capacity() != 3 {
		t.Fatalf("stats: seen=%d cap=%d", ring.Seen(), ring.Capacity())
	}
}

// TestRoutes: listing filters and paginates; a user is refused; download
// is audited and sends the ring oldest first.
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
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{7}, 32), false)
	auditLog := audit.NewLog(db)
	ring := New(100)
	log := slog.New(ring.Wrap(slog.NewTextHandler(io.Discard, nil)))
	log.Info("starting zanskar", "version", "test")
	log.Warn("guacd dial failed", "target", "t1")
	mux := http.NewServeMux()
	(&API{Ring: ring, Audit: auditLog, Log: quiet}).Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: quiet}
	srv := mw.Authenticate(mw.CSRF(mux))
	login := func(name string, role user.Role) *http.Cookie {
		u := &user.User{Username: name, DisplayName: name, Roles: []user.Role{role}}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		tok, _, err := sessions.Create(ctx, u.ID, "203.0.113.9", "test", true)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: auth.CookieName, Value: tok}
	}
	admin, plain := login("root", user.RoleAdmin), login("alice", user.RoleUser)
	get := func(path string, c *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = "203.0.113.9:4321"
		req.AddCookie(c)
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		return rr
	}
	rr := get("/api/v1/admin/logs?level=warn", admin)
	var out struct {
		Items    []Record `json:"items"`
		Capacity int      `json:"capacity"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != 200 || len(out.Items) != 1 || out.Items[0].Msg != "guacd dial failed" || out.Capacity != 100 {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}
	if rr := get("/api/v1/admin/logs?q=VERSION", admin); rr.Code != 200 || !strings.Contains(rr.Body.String(), "starting zanskar") {
		t.Fatalf("q: %d %s", rr.Code, rr.Body.String())
	}
	if rr := get("/api/v1/admin/logs?level=loud", admin); rr.Code != 400 {
		t.Fatalf("bad level: %d", rr.Code)
	}
	if rr := get("/api/v1/admin/logs", plain); rr.Code != 403 {
		t.Fatalf("user: %d", rr.Code)
	}
	rr = get("/api/v1/admin/logs/download", admin)
	lines := strings.Split(strings.TrimSpace(rr.Body.String()), "\n")
	if rr.Code != 200 || len(lines) != 2 || !strings.Contains(lines[0], "starting zanskar") || rr.Header().Get("Content-Disposition") == "" {
		t.Fatalf("download: %d %s", rr.Code, rr.Body.String())
	}
	events, _, _ := auditLog.List(ctx, audit.Filter{Action: "logs.download"})
	if len(events) != 1 {
		t.Fatalf("download must be audited once, got %d", len(events))
	}
}
