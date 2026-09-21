// SPDX-License-Identifier: Apache-2.0

package connect

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
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

type shadowEnv struct {
	srv      *httptest.Server
	reg      *gateway.Registry
	auditLog *audit.Log
	sessions *auth.Sessions
	users    *user.Repo
}

func newShadowEnv(t *testing.T) *shadowEnv {
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
	e := &shadowEnv{reg: gateway.NewRegistry(), auditLog: audit.NewLog(db), users: user.NewRepo(db)}
	e.sessions = auth.NewSessions(db, bytes.Repeat([]byte{3}, 32), false)
	h := &ShadowHandler{Registry: e.reg, Audit: e.auditLog, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: e.sessions, Users: e.users, Log: log}
	e.srv = httptest.NewServer(mw.Authenticate(mux))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *shadowEnv) cookieFor(t *testing.T, name string, roles ...user.Role) *http.Cookie {
	t.Helper()
	u := &user.User{Username: name, DisplayName: name, Roles: roles}
	if err := e.users.Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	tok, _, err := e.sessions.Create(context.Background(), u.ID, "127.0.0.1", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: auth.CookieName, Value: tok}
}

func dialShadow(t *testing.T, e *shadowEnv, sessionID string, c *http.Cookie) (*websocket.Conn, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	opts := &websocket.DialOptions{HTTPHeader: http.Header{"Cookie": []string{c.String()}}}
	ws, res, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(e.srv.URL, "http")+"/ws/shadow/"+sessionID, opts) //nolint:bodyclose // library closes the handshake body
	if err != nil {
		if res != nil {
			return nil, res.StatusCode
		}
		t.Fatal(err)
	}
	return ws, res.StatusCode
}

func TestShadowTerminalReplayAndLive(t *testing.T) {
	e := newShadowEnv(t)
	auditor := e.cookieFor(t, "auditor", user.RoleAuditor)
	e.reg.Add(context.Background(), gateway.Live{SessionID: "s1", UserID: "owner", TargetID: "t1", Protocol: "ssh"})
	tap := e.reg.Tap("s1")
	tap.Write([]byte("$ ls\r\nfile\r\n"))

	ws, code := dialShadow(t, e, "s1", auditor)
	if ws == nil {
		t.Fatalf("dial failed with %d", code)
	}
	defer ws.CloseNow()
	ctx := context.Background()
	_, first, err := ws.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ctl map[string]any
	_ = json.Unmarshal(first, &ctl)
	if ctl["t"] != "ready" || ctl["replay"] != true {
		t.Fatalf("expected ready with replay, got %s", first)
	}
	typ, replay, err := ws.Read(ctx)
	if err != nil || typ != websocket.MessageBinary || string(replay) != "$ ls\r\nfile\r\n" {
		t.Fatalf("replay: %v %q", err, replay)
	}
	// Watcher input is ignored; live output arrives.
	_ = ws.Write(ctx, websocket.MessageBinary, []byte("rm -rf /\r"))
	tap.Write([]byte("live!"))
	_, live, err := ws.Read(ctx)
	if err != nil || string(live) != "live!" {
		t.Fatalf("live: %v %q", err, live)
	}
	// Session ends -> end frame.
	e.reg.Remove("s1")
	_, end, err := ws.Read(ctx)
	if err != nil || !strings.Contains(string(end), `"session_ended"`) {
		t.Fatalf("end: %v %s", err, end)
	}
	events, _, err := e.auditLog.List(ctx, audit.Filter{Action: "session.shadow.start"})
	if err != nil || len(events) != 1 {
		t.Fatalf("expected one shadow.start audit event, got %d (%v)", len(events), err)
	}
}

func TestShadowAuthz(t *testing.T) {
	e := newShadowEnv(t)
	e.reg.Add(context.Background(), gateway.Live{SessionID: "s1", UserID: "owner", TargetID: "t1", Protocol: "ssh"})
	plain := e.cookieFor(t, "bob", user.RoleUser)
	if ws, code := dialShadow(t, e, "s1", plain); ws != nil || code != http.StatusForbidden {
		t.Fatalf("plain user: ws=%v code=%d", ws != nil, code)
	}
	admin := e.cookieFor(t, "root", user.RoleAdmin)
	if ws, code := dialShadow(t, e, "nope", admin); ws != nil || code != http.StatusNotFound {
		t.Fatalf("unknown session: ws=%v code=%d", ws != nil, code)
	}
	if ws, code := dialShadow(t, e, "s1", &http.Cookie{Name: auth.CookieName, Value: "bogus"}); ws != nil || code != http.StatusUnauthorized {
		t.Fatalf("anonymous: ws=%v code=%d", ws != nil, code)
	}
}
