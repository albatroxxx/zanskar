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
	"github.com/albatroxxx/zanskar/internal/asg"
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/protocol"
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
	asgs     *asg.Repo
	audit    *audit.Log
	users    *user.Repo
	policies *policy.Repo
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
	e := &env{db: db, sessions: session.NewRepo(db), requests: access.NewRepo(db), targets: target.NewRepo(db), asgs: asg.NewRepo(db), audit: audit.NewLog(db),
		users: users, policies: policy.NewRepo(db), cookies: map[string]*http.Cookie{}, ids: map[string]string{}}
	h := &Handler{Sessions: e.sessions, Requests: e.requests, Targets: e.targets, ASGs: e.asgs, Audit: e.audit, Log: log, Users: e.users, Policies: e.policies}
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
		{Name: "win 1", Address: "10.0.0.7", OSFamily: "windows"},
		{Name: "orders pg", Address: "10.0.0.8", Engine: "postgres", TLSMode: "require", Ports: map[target.Protocol]int{"database": 5432}},
	} {
		if err := e.targets.Create(ctx, tg); err != nil {
			t.Fatal(err)
		}
	}
	now := store.TimeArg(time.Now())
	// web 2 waits on two decisions, a host key and a certificate: one host
	// needing attention, whatever the per-reason counts add up to.
	if _, err := e.db.ExecContext(ctx, e.db.Rebind(`UPDATE targets SET host_key_status = 'pending', tls_fingerprint_pending = 'ab', updated_at = ? WHERE name = 'web 2'`), now); err != nil {
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
	group := &asg.Group{Name: "web-fleet", Region: "eu-central-1", ExternalName: "web-fleet", RoleARN: "arn:aws:iam::123456789012:role/zanskar-read", OSFamily: "linux"}
	if err := e.asgs.Create(ctx, group); err != nil {
		t.Fatal(err)
	}
	for _, in := range []*asg.Instance{
		{GroupID: group.ID, InstanceID: "i-1", LifecycleState: "InService", ProbeHealth: "healthy"},
		{GroupID: group.ID, InstanceID: "i-2", LifecycleState: "InService", ProbeHealth: "unhealthy"},
	} {
		if _, _, err := e.asgs.UpsertInstance(ctx, in); err != nil {
			t.Fatal(err)
		}
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
	// Hosts only: the tile opens the Hosts page (2026-10-30).
	if got := num(t, out, "targets", "active"); got != 3 {
		t.Errorf("targets.active = %v, want 3", got)
	}
	if got := num(t, out, "targets", "needing_attention"); got != 1 {
		t.Errorf("targets.needing_attention = %v, want 1 (one host, two reasons)", got)
	}
	if got := num(t, out, "targets", "certificate_pending"); got != 1 {
		t.Errorf("targets.certificate_pending = %v, want 1", got)
	}
	if got := num(t, out, "targets", "host_key_pending"); got != 1 {
		t.Errorf("targets.host_key_pending = %v, want 1", got)
	}
	if got := num(t, out, "targets", "host_key_changed"); got != 0 {
		t.Errorf("targets.host_key_changed = %v, want 0", got)
	}
	if got := num(t, out, "inventory", "hosts"); got != 3 {
		t.Errorf("inventory.hosts = %v, want 3", got)
	}
	if got := num(t, out, "inventory", "hosts_by_os", "windows"); got != 1 {
		t.Errorf("inventory.hosts_by_os.windows = %v, want 1", got)
	}
	if got := num(t, out, "inventory", "databases_by_engine", "postgres"); got != 1 {
		t.Errorf("inventory.databases_by_engine.postgres = %v, want 1", got)
	}
	if got := num(t, out, "autoscaling", "groups"); got != 1 {
		t.Errorf("autoscaling.groups = %v, want 1", got)
	}
	if got := num(t, out, "autoscaling", "instances"); got != 2 {
		t.Errorf("autoscaling.instances = %v, want 2", got)
	}
	if got := num(t, out, "autoscaling", "healthy_instances"); got != 1 {
		t.Errorf("autoscaling.healthy_instances = %v, want 1", got)
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

// TestAdminOverviewPosture (2026-10-31): the overview carries the security
// posture: standing grants without MFA and the policies holding them, the
// active administrators, accounts not yet enrolled in an authenticator, and
// dormant ones. Counts only, as every overview number is.
func TestAdminOverviewPosture(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	hash, err := user.HashPassword("a password of its own")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.users.Create(ctx, &user.User{Username: "bob", DisplayName: "Bob", PasswordHash: hash, Roles: []user.Role{user.RoleUser}}); err != nil {
		t.Fatal(err)
	}
	open := policy.Grant{Kind: protocol.KindHost, Targets: []policy.GrantTarget{{ID: "t1", Protocols: []string{"ssh"}}}, Access: policy.AccessStanding}
	asked := open
	asked.RequireMFA = true
	if err := e.policies.Create(ctx, &policy.Policy{Name: "open", Enabled: true, Subjects: []policy.Subject{{Kind: policy.SubjectUser, ID: e.ids["alice"]}}, Grants: []policy.Grant{open, asked}}); err != nil {
		t.Fatal(err)
	}
	rr, out := e.get(t, "/api/v1/admin/overview", "root")
	if rr.Code != http.StatusOK {
		t.Fatalf("overview: %d %s", rr.Code, rr.Body)
	}
	p := out["posture"].(map[string]any)
	if p["admins"] != float64(1) || p["not_enrolled"] != float64(1) || p["dormant"] != float64(0) {
		t.Fatalf("posture: %v", p)
	}
	if exp := p["standing_no_mfa"].(map[string]any); exp["grants"] != float64(1) || exp["policies"] != float64(1) {
		t.Fatalf("standing without MFA: %v", exp)
	}
}
