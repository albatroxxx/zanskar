// SPDX-License-Identifier: Apache-2.0

package overview

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/access"
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/user"
)

type env struct {
	srv      http.Handler
	db       *store.DB
	sessions *session.Repo
	requests *access.Repo
	targets  *target.Repo
	audit    *audit.Log
	cookies  map[string]*http.Cookie
	ids      map[string]string
}

// newEnv wires the overview handler behind the real auth middleware with an
// admin, an auditor and a plain user.
func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	db := storetest.Open(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, []byte("0123456789abcdef0123456789abcdef"), false)
	e := &env{db: db, sessions: session.NewRepo(db), requests: access.NewRepo(db), targets: target.NewRepo(db), audit: audit.NewLog(db), cookies: map[string]*http.Cookie{}, ids: map[string]string{}}
	h := &Handler{Sessions: e.sessions, Requests: e.requests, Targets: e.targets, Audit: e.audit, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	e.srv = mw.Authenticate(mw.CSRF(mux))
	for name, role := range map[string]user.Role{"root": user.RoleAdmin, "reviewer": user.RoleAuditor, "alice": user.RoleUser} {
		u := &user.User{Username: name, DisplayName: name, Roles: []user.Role{role}}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		tok, _, err := sessions.Create(ctx, u.ID, "203.0.113.9", "test", true)
		if err != nil {
			t.Fatal(err)
		}
		e.cookies[name] = &http.Cookie{Name: auth.CookieName, Value: tok}
		e.ids[name] = u.ID
	}
	return e
}

func (e *env) get(t *testing.T, path, who string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = "203.0.113.9:4321"
	req.AddCookie(e.cookies[who])
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

// seed stands up the rows the overviews count: two targets (one with a pending
// host key), an open and an ended session, a pending access request, and a
// day's worth of audit events including an old one outside the window.
func seed(t *testing.T, e *env) {
	t.Helper()
	ctx := context.Background()
	for _, tg := range []*target.Target{
		{Name: "web 1", Address: "10.0.0.5", OSFamily: "linux"},
		{Name: "web 2", Address: "10.0.0.6", OSFamily: "linux"},
	} {
		if err := e.targets.Create(ctx, tg); err != nil {
			t.Fatal(err)
		}
	}
	now := store.TimeArg(time.Now())
	if _, err := e.db.ExecContext(ctx, e.db.Rebind(`UPDATE targets SET host_key_status = 'pending', updated_at = ? WHERE name = 'web 2'`), now); err != nil {
		t.Fatal(err)
	}
	var t1 string
	if err := e.db.QueryRowContext(ctx, `SELECT id FROM targets WHERE name = 'web 1'`).Scan(&t1); err != nil {
		t.Fatal(err)
	}
	open := &session.Session{UserID: e.ids["alice"], TargetID: t1, Protocol: "ssh", ClientIP: "10.0.0.1"}
	if err := e.sessions.Start(ctx, open); err != nil {
		t.Fatal(err)
	}
	ended := &session.Session{UserID: e.ids["alice"], TargetID: t1, Protocol: "ssh", ClientIP: "10.0.0.1"}
	if err := e.sessions.Start(ctx, ended); err != nil {
		t.Fatal(err)
	}
	if err := e.sessions.End(ctx, ended.ID, session.EndUserExit); err != nil {
		t.Fatal(err)
	}
	req := &access.Request{UserID: e.ids["alice"], TargetID: t1, Protocol: "ssh", Reason: "deploy", RequestedMinutes: 30}
	if err := e.requests.Create(ctx, req); err != nil {
		t.Fatal(err)
	}
	actor := audit.Actor{UserID: e.ids["alice"], IP: "10.0.0.1"}
	for _, ev := range []audit.Event{
		actor.Event(audit.UserLogin, "user", e.ids["alice"], audit.Failure, map[string]string{"reason": "bad_password"}),
		actor.Event(audit.UserLogin, "user", e.ids["alice"], audit.Failure, map[string]string{"reason": "bad_password"}),
		actor.Event(audit.SessionConnect, "target", t1, audit.Failure, map[string]string{"reason": "no_policy"}),
		actor.Event(audit.SessionConnect, "target", t1, audit.Success, nil),
		actor.Event(audit.RecordingView, "recording", "r1", audit.Success, nil),
		actor.Event(audit.RecordingDownload, "recording", "r1", audit.Success, nil),
	} {
		if _, err := e.audit.Record(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	// An event older than the window must not be tallied.
	old, err := e.audit.Record(ctx, actor.Event(audit.UserLogin, "user", e.ids["alice"], audit.Failure, map[string]string{"reason": "bad_password"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.ExecContext(ctx, e.db.Rebind(`UPDATE audit_events SET ts = ? WHERE id = ?`), store.TimeArg(time.Now().Add(-25*time.Hour)), old.ID); err != nil {
		t.Fatal(err)
	}
}

func num(t *testing.T, m map[string]any, keys ...string) float64 {
	t.Helper()
	var cur any = m
	for _, k := range keys {
		obj, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("no object at %v in %v", k, m)
		}
		cur = obj[k]
	}
	f, ok := cur.(float64)
	if !ok {
		t.Fatalf("no number at %v in %v", keys, m)
	}
	return f
}

func TestAdminOverview(t *testing.T) {
	e := newEnv(t)
	seed(t, e)
	rr, out := e.get(t, "/api/v1/admin/overview", "root")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
	for want, keys := range map[float64][]string{
		1: {"sessions", "open"},
		2: {"sessions", "started_24h"},
	} {
		if got := num(t, out, keys...); got != want {
			t.Errorf("%v = %v, want %v", keys, got, want)
		}
	}
	if got := num(t, out, "pending_requests"); got != 1 {
		t.Errorf("pending_requests = %v, want 1", got)
	}
	if got := num(t, out, "targets", "active"); got != 2 {
		t.Errorf("targets.active = %v, want 2", got)
	}
	if got := num(t, out, "targets", "host_key_pending"); got != 1 {
		t.Errorf("targets.host_key_pending = %v, want 1", got)
	}
	if got := num(t, out, "targets", "host_key_changed"); got != 0 {
		t.Errorf("targets.host_key_changed = %v, want 0", got)
	}
	// Two in-window login failures; the third is 25 hours old.
	if got := num(t, out, "audit_24h", "failed_logins"); got != 2 {
		t.Errorf("audit_24h.failed_logins = %v, want 2", got)
	}
	if got := num(t, out, "audit_24h", "refused_connects"); got != 1 {
		t.Errorf("audit_24h.refused_connects = %v, want 1", got)
	}
	if got := num(t, out, "audit_24h", "failures"); got != 3 {
		t.Errorf("audit_24h.failures = %v, want 3", got)
	}
}

func TestAuditOverview(t *testing.T) {
	e := newEnv(t)
	seed(t, e)
	for _, who := range []string{"root", "reviewer"} {
		rr, out := e.get(t, "/api/v1/audit/overview", who)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", who, rr.Code, rr.Body.String())
		}
		if got := num(t, out, "sessions", "open"); got != 1 {
			t.Errorf("%s: sessions.open = %v, want 1", who, got)
		}
		if got := num(t, out, "events_24h", "failures"); got != 3 {
			t.Errorf("%s: events_24h.failures = %v, want 3", who, got)
		}
		if got := num(t, out, "reviews_24h", "recording_views"); got != 1 {
			t.Errorf("%s: reviews_24h.recording_views = %v, want 1", who, got)
		}
		if got := num(t, out, "reviews_24h", "recording_downloads"); got != 1 {
			t.Errorf("%s: reviews_24h.recording_downloads = %v, want 1", who, got)
		}
	}
}

// TestOverviewRoles pins the guards: a user is refused everywhere, an auditor
// is refused the admin overview, and nobody unauthenticated gets in.
func TestOverviewRoles(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		path, who string
		want      int
	}{
		{"/api/v1/admin/overview", "alice", http.StatusForbidden},
		{"/api/v1/admin/overview", "reviewer", http.StatusForbidden},
		{"/api/v1/audit/overview", "alice", http.StatusForbidden},
	} {
		rr, _ := e.get(t, tc.path, tc.who)
		if rr.Code != tc.want {
			t.Errorf("%s as %s: status %d, want %d", tc.path, tc.who, rr.Code, tc.want)
		}
	}
	req := httptest.NewRequest("GET", "/api/v1/admin/overview", nil)
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: status %d, want 401", rr.Code)
	}
}

// TestOverviewRecordsNoAuditEvent pins the ADR 0029 line: counts are not
// content, so reading an overview must not grow the audit log.
func TestOverviewRecordsNoAuditEvent(t *testing.T) {
	e := newEnv(t)
	seed(t, e)
	count := func() int {
		var n int
		if err := e.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM audit_events`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count()
	if rr, _ := e.get(t, "/api/v1/admin/overview", "root"); rr.Code != http.StatusOK {
		t.Fatalf("admin overview: %d", rr.Code)
	}
	if rr, _ := e.get(t, "/api/v1/audit/overview", "reviewer"); rr.Code != http.StatusOK {
		t.Fatalf("audit overview: %d", rr.Code)
	}
	if after := count(); after != before {
		t.Errorf("audit log grew from %d to %d on overview reads", before, after)
	}
}
