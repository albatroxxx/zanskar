// SPDX-License-Identifier: Apache-2.0

package apps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/access"
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/group"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/user"
)

const clientAddr = "203.0.113.5:4000"

// fixture is a gateway with alice, a policy granting her http on everything
// tagged app=yes, and one application, wiki, whose upstream is a test server
// that remembers the last request it saw.
type fixture struct {
	t        *testing.T
	ctx      context.Context
	db       *store.DB
	h        *Handler
	console  http.Handler
	alice    *user.User
	cookie   *http.Cookie
	csrf     string
	sessions *auth.Sessions
	authSID  string
	wiki     *target.Target
	upstream *httptest.Server
	policies *policy.Repo
	policyID string
	auditLog *audit.Log
	access   *session.Repo

	mu   sync.Mutex
	last *http.Request
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	db := storetest.Open(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f := &fixture{t: t, ctx: ctx, db: db, auditLog: audit.NewLog(db), access: session.NewRepo(db)}

	users := user.NewRepo(db)
	f.alice = &user.User{Username: "alice", DisplayName: "Alice", Roles: []user.Role{user.RoleUser}}
	if err := users.Create(ctx, f.alice); err != nil {
		t.Fatal(err)
	}
	groups := group.NewRepo(db)
	g := &group.Group{Name: "ops"}
	if err := groups.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := groups.AddMember(ctx, g.ID, f.alice.ID); err != nil {
		t.Fatal(err)
	}
	f.policies = policy.NewRepo(db)
	p := &policy.Policy{Name: "apps", GroupID: g.ID, Enabled: true, IdleTimeoutMinutes: 15, Selector: policy.Selector{Tags: map[string]string{"app": "yes"}}, Protocols: []string{"http"}}
	if err := f.policies.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	f.policyID = p.ID

	f.upstream = httptest.NewServer(http.HandlerFunc(f.serveUpstream))
	t.Cleanup(f.upstream.Close)
	targets := target.NewRepo(db)
	f.wiki = &target.Target{Name: "Wiki", AppUpstream: f.upstream.URL, Tags: map[string]string{"app": "yes"}}
	if err := targets.Create(ctx, f.wiki); err != nil {
		t.Fatal(err)
	}

	f.sessions = auth.NewSessions(db, bytes.Repeat([]byte{2}, 32), false)
	tok, sess, err := f.sessions.Create(ctx, f.alice.ID, "203.0.113.5", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	f.cookie, f.csrf, f.authSID = &http.Cookie{Name: auth.CookieName, Value: tok}, f.sessions.CSRFToken(sess.ID), sess.ID

	f.h = &Handler{
		Targets: targets, Gate: &access.Gate{Policies: f.policies, Grants: access.NewRepo(db)}, Sessions: f.access, Auth: f.sessions,
		Repo: NewRepo(db), Registry: gateway.NewRegistry(), Audit: f.auditLog, Log: log, Prober: &target.Prober{AllowLoopback: true},
		Domain: func() string { return "apps.test" }, PublicURL: "https://gw.test",
	}
	mux := http.NewServeMux()
	f.h.Register(mux)
	mw := &auth.Middleware{Sessions: f.sessions, Users: users, Log: log}
	f.console = mw.Authenticate(mw.CSRF(mux))
	return f
}

// serveUpstream is the application: it remembers the request and answers by
// path, with a redirect to its own origin, cookies a proxy must sanitise, a
// WebSocket echo, or a greeting.
func (f *fixture) serveUpstream(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.last = r.Clone(context.Background())
	f.mu.Unlock()
	switch r.URL.Path {
	case "/redirect":
		http.Redirect(w, r, f.upstream.URL+"/login?from=x", http.StatusFound)
	case "/cookies":
		w.Header().Add("Set-Cookie", "sid=1; Domain=apps.test; Path=/; HttpOnly")
		w.Header().Add("Set-Cookie", "zanskar_app=evil; Path=/")
		w.Header().Add("Set-Cookie", "plain=2; Path=/")
		_, _ = io.WriteString(w, "ok")
	case "/ws":
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		typ, msg, err := c.Read(r.Context())
		if err != nil {
			return
		}
		_ = c.Write(r.Context(), typ, append([]byte("echo: "), msg...))
		_ = c.Close(websocket.StatusNormalClosure, "")
	default:
		_, _ = fmt.Fprintf(w, "hello %s", r.URL.Path)
	}
}

func (f *fixture) seen() *http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

// app sends a request to an application host as alice's browser would.
func (f *fixture) app(method, rawURL string, hdr http.Header, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, rawURL, nil)
	req.RemoteAddr = clientAddr
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	maps.Copy(req.Header, hdr)
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	rr := httptest.NewRecorder()
	f.h.ServeHTTP(rr, req)
	return rr
}

// launch calls the console route as the /launch page does.
func (f *fixture) launch(body string) (int, map[string]any) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/applications/launch", strings.NewReader(body))
	req.RemoteAddr = clientAddr
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", f.csrf)
	req.AddCookie(f.cookie)
	rr := httptest.NewRecorder()
	f.console.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func cookieNamed(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// open walks the whole hand-off for alice on wiki and returns the
// application cookie and the session id.
func (f *fixture) open(next string) (*http.Cookie, string) {
	f.t.Helper()
	rr := f.app(http.MethodGet, "http://wiki.apps.test"+next, nil)
	if rr.Code != http.StatusFound {
		f.t.Fatalf("first visit: %d %s", rr.Code, rr.Body)
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil || loc.Host != "gw.test" || loc.Path != LaunchPath || loc.Query().Get("app") != "wiki" || loc.Query().Get("next") != next {
		f.t.Fatalf("bounce to the console: %q", rr.Header().Get("Location"))
	}
	stateCookie := cookieNamed(rr.Result(), stateBase)
	if stateCookie == nil || stateCookie.Value != loc.Query().Get("state") || !stateCookie.HttpOnly {
		f.t.Fatalf("state cookie: %+v", stateCookie)
	}
	code, out := f.launch(fmt.Sprintf(`{"app":"wiki","state":%q,"next":%q}`, stateCookie.Value, next))
	if code != http.StatusOK {
		f.t.Fatalf("launch: %d %v", code, out)
	}
	enter, _ := out["url"].(string)
	if !strings.HasPrefix(enter, "https://wiki.apps.test"+enterPath+"?") {
		f.t.Fatalf("enter url: %q", enter)
	}
	rr = f.app(http.MethodGet, enter, nil, stateCookie)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != next {
		f.t.Fatalf("enter: %d %q %s", rr.Code, rr.Header().Get("Location"), rr.Body)
	}
	appCookie := cookieNamed(rr.Result(), cookieBase)
	if appCookie == nil || appCookie.Value == "" || !appCookie.HttpOnly || appCookie.SameSite != http.SameSiteLaxMode || appCookie.Domain != "" {
		f.t.Fatalf("application cookie: %+v", appCookie)
	}
	if cleared := cookieNamed(rr.Result(), stateBase); cleared == nil || cleared.MaxAge >= 0 {
		f.t.Fatalf("state cookie not cleared: %+v", cleared)
	}
	live := f.h.Registry.List()
	if len(live) != 1 || live[0].Protocol != "http" || live[0].UserID != f.alice.ID || live[0].PolicyID != f.policyID {
		f.t.Fatalf("registry: %+v", live)
	}
	return appCookie, live[0].SessionID
}

func (f *fixture) events(action string) []audit.Event {
	f.t.Helper()
	items, _, err := f.auditLog.List(f.ctx, audit.Filter{Action: action, Limit: 50})
	if err != nil {
		f.t.Fatal(err)
	}
	return items
}

func (f *fixture) waitEnded(id string) *session.Session {
	f.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s, err := f.access.Get(f.ctx, id)
		if err != nil {
			f.t.Fatal(err)
		}
		if s.EndedAt != nil {
			return s
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("session %s did not end", id)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestFlow: a browser with no session is sent to the console with a state;
// the console issues a code; the application host checks state and code,
// opens a session and sets a host-only cookie; requests are proxied with the
// gateway's cookies and any identity header stripped, Authorization kept and
// the forwarded headers set; an upstream redirect to itself comes back on the
// public address; upstream cookies lose their Domain and never take the
// gateway's names; the session ends when an administrator terminates it.
func TestFlow(t *testing.T) {
	f := newFixture(t)
	appCookie, sid := f.open("/dash?x=1")

	s, err := f.access.Get(f.ctx, sid)
	if err != nil || s.Protocol != "http" || s.TargetID != f.wiki.ID || s.PolicyID != f.policyID || s.ClientIP != "203.0.113.5" || s.EndedAt != nil {
		t.Fatalf("session row: %v %+v", err, s)
	}
	if ev := f.events(audit.AppSessionStart); len(ev) != 1 || ev[0].ObjectID != sid || ev[0].ActorUserID != f.alice.ID {
		t.Fatalf("start event: %+v", ev)
	}
	if ev := f.events(audit.SessionConnect); len(ev) != 1 || ev[0].Outcome != audit.Success {
		t.Fatalf("connect event: %+v", ev)
	}

	hdr := http.Header{"X-Forwarded-User": {"root"}, "X-Remote-User": {"root"}, "Authorization": {"Bearer abc"}, "Cookie": {"other=1; zanskar_session=stolen"}}
	rr := f.app(http.MethodGet, "http://wiki.apps.test/dash?x=1", hdr, appCookie)
	if rr.Code != http.StatusOK || rr.Body.String() != "hello /dash" {
		t.Fatalf("proxied: %d %s", rr.Code, rr.Body)
	}
	got := f.seen()
	upURL, _ := url.Parse(f.upstream.URL)
	if got.Host != upURL.Host || got.URL.RawQuery != "x=1" {
		t.Errorf("upstream saw host %q query %q", got.Host, got.URL.RawQuery)
	}
	if got.Header.Get("X-Forwarded-User") != "" || got.Header.Get("X-Remote-User") != "" {
		t.Errorf("identity headers reached the upstream: %v", got.Header)
	}
	if got.Header.Get("Authorization") != "Bearer abc" {
		t.Errorf("Authorization did not reach the upstream: %q", got.Header.Get("Authorization"))
	}
	if got.Header.Get("Cookie") != "other=1" {
		t.Errorf("cookies reached the upstream: %q", got.Header.Get("Cookie"))
	}
	if got.Header.Get("X-Forwarded-Host") != "wiki.apps.test" || got.Header.Get("X-Forwarded-Proto") != "https" || got.Header.Get("X-Forwarded-For") != "203.0.113.5" {
		t.Errorf("forwarded headers: %v", got.Header)
	}

	rr = f.app(http.MethodGet, "http://wiki.apps.test/redirect", nil, appCookie)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "https://wiki.apps.test/login?from=x" {
		t.Errorf("redirect rewrite: %d %q", rr.Code, rr.Header().Get("Location"))
	}
	rr = f.app(http.MethodGet, "http://wiki.apps.test/cookies", nil, appCookie)
	if got := rr.Header().Values("Set-Cookie"); len(got) != 2 || got[0] != "sid=1; Path=/; HttpOnly" || got[1] != "plain=2; Path=/" {
		t.Errorf("Set-Cookie sanitising: %q", got)
	}

	// A fetch without a session is told no; a page is sent to sign in.
	rr = f.app(http.MethodGet, "http://wiki.apps.test/api/data", http.Header{"Sec-Fetch-Mode": {"cors"}})
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("fetch without session: %d", rr.Code)
	}
	rr = f.app(http.MethodPost, "http://wiki.apps.test/api/data", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("post without session: %d", rr.Code)
	}

	// Terminated by an administrator: the row ends, the end is audited, the
	// cookie stops working and the browser is sent back to sign in.
	if !f.h.Registry.Terminate(sid) {
		t.Fatal("session not in the registry")
	}
	if s := f.waitEnded(sid); s.EndReason != session.EndAdminTerminated {
		t.Errorf("end reason: %q", s.EndReason)
	}
	if ev := f.events(audit.AppSessionEnd); len(ev) != 1 || ev[0].ObjectID != sid {
		t.Fatalf("end event: %+v", ev)
	}
	if f.h.Registry.Count() != 0 {
		t.Error("registry still holds the session")
	}
	rr = f.app(http.MethodGet, "http://wiki.apps.test/dash", nil, appCookie)
	if rr.Code != http.StatusFound || !strings.HasPrefix(rr.Header().Get("Location"), "https://gw.test/launch?") {
		t.Errorf("after terminate: %d %q", rr.Code, rr.Header().Get("Location"))
	}
	if _, err := f.h.Repo.Lookup(f.ctx, hashToken(appCookie.Value)); err == nil {
		t.Error("the cookie's row survived the end")
	}
}

// TestWebSocket: an upgrade goes through the proxy like any request, with
// the session checked the same way.
func TestWebSocket(t *testing.T) {
	f := newFixture(t)
	appCookie, _ := f.open("/")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = clientAddr
		f.h.ServeHTTP(w, r)
	}))
	defer srv.Close()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, resp, err := websocket.Dial(ctx, "ws://wiki.apps.test/ws", &websocket.DialOptions{HTTPClient: client, HTTPHeader: http.Header{"Cookie": {appCookie.String()}}})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("dial through the proxy: %v", err)
	}
	defer c.CloseNow()
	if err := c.Write(ctx, websocket.MessageText, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	_, msg, err := c.Read(ctx)
	if err != nil || string(msg) != "echo: ping" {
		t.Fatalf("echo: %q %v", msg, err)
	}
	// Without the cookie the upgrade is refused before any upstream is dialled.
	c2, resp2, err := websocket.Dial(ctx, "ws://wiki.apps.test/ws", &websocket.DialOptions{HTTPClient: client})
	if resp2 != nil && resp2.Body != nil {
		_ = resp2.Body.Close()
	}
	if err == nil {
		c2.CloseNow()
		t.Fatal("upgrade without a session succeeded")
	}
}

// TestHandoffRefusals: every way a code can be presented other than as
// issued is refused, and the refusal never opens a session.
func TestHandoffRefusals(t *testing.T) {
	f := newFixture(t)
	start := func() (*http.Cookie, string) {
		t.Helper()
		rr := f.app(http.MethodGet, "http://wiki.apps.test/", nil)
		sc := cookieNamed(rr.Result(), stateBase)
		code, out := f.launch(fmt.Sprintf(`{"app":"wiki","state":%q,"next":"/"}`, sc.Value))
		if code != http.StatusOK {
			t.Fatalf("launch: %d %v", code, out)
		}
		return sc, out["url"].(string)
	}
	sc, enter := start()
	// No state cookie.
	if rr := f.app(http.MethodGet, enter, nil); rr.Code != http.StatusForbidden {
		t.Errorf("without the state cookie: %d", rr.Code)
	}
	// A state cookie that is not the one in the query.
	other := &http.Cookie{Name: stateBase, Value: strings.Repeat("x", 43)}
	if rr := f.app(http.MethodGet, enter, nil, other); rr.Code != http.StatusForbidden {
		t.Errorf("mismatched state: %d", rr.Code)
	}
	// Another client.
	req := httptest.NewRequest(http.MethodGet, enter, nil)
	req.RemoteAddr = "198.51.100.9:5000"
	req.AddCookie(sc)
	rr := httptest.NewRecorder()
	f.h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("another client's address: %d", rr.Code)
	}
	// The code is spent by the refusals above; a fresh one works once only.
	sc, enter = start()
	if rr := f.app(http.MethodGet, enter, nil, sc); rr.Code != http.StatusSeeOther {
		t.Fatalf("fresh code: %d %s", rr.Code, rr.Body)
	}
	if rr := f.app(http.MethodGet, enter, nil, sc); rr.Code != http.StatusForbidden {
		t.Errorf("replayed code: %d", rr.Code)
	}
	// A code for another application.
	if err := f.h.Targets.Create(f.ctx, &target.Target{Name: "docs", AppUpstream: f.upstream.URL, Tags: map[string]string{"app": "yes"}}); err != nil {
		t.Fatal(err)
	}
	sc, enter = start()
	swapped := strings.Replace(enter, "https://wiki.apps.test", "https://docs.apps.test", 1)
	if rr := f.app(http.MethodGet, swapped, nil, sc); rr.Code != http.StatusForbidden {
		t.Errorf("code for another application: %d", rr.Code)
	}
	if f.h.Registry.Count() != 1 {
		t.Errorf("sessions open: %d, want the one the fresh code opened", f.h.Registry.Count())
	}
	// The return path can only be a path on the application.
	for in, want := range map[string]string{"/a/b?c=d": "/a/b?c=d", "//evil.test/x": "/", "https://evil.test": "/", "": "/", "/\\evil": "/", "/ok\r\nSet-Cookie: x": "/"} {
		if got := safePath(in); got != want {
			t.Errorf("safePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestLaunchRefusals: the console route refuses what the gate refuses,
// audits each refusal as session.connect, and names what is not configured.
func TestLaunchRefusals(t *testing.T) {
	f := newFixture(t)
	state := strings.Repeat("s", 43)
	if code, out := f.launch(`{"app":"Not a label!","state":"` + state + `","next":"/"}`); code != http.StatusBadRequest {
		t.Errorf("bad label: %d %v", code, out)
	}
	if code, out := f.launch(`{"app":"wiki","state":"short","next":"/"}`); code != http.StatusBadRequest {
		t.Errorf("bad state: %d %v", code, out)
	}
	if code, out := f.launch(`{"app":"nothing","state":"` + state + `","next":"/"}`); code != http.StatusNotFound {
		t.Errorf("unknown application: %d %v", code, out)
	}
	// Approval-gated: the policy makes alice eligible, not admitted.
	p, err := f.policies.Get(f.ctx, f.policyID)
	if err != nil {
		t.Fatal(err)
	}
	p.RequireApproval = true
	if err := f.policies.Update(f.ctx, p); err != nil {
		t.Fatal(err)
	}
	if code, out := f.launch(`{"app":"wiki","state":"` + state + `","next":"/"}`); code != http.StatusForbidden || out["code"] != access.CodeApprovalRequired {
		t.Errorf("approval-gated: %d %v", code, out)
	}
	// No policy at all.
	if err := f.policies.Delete(f.ctx, f.policyID); err != nil {
		t.Fatal(err)
	}
	if code, out := f.launch(`{"app":"wiki","state":"` + state + `","next":"/"}`); code != http.StatusForbidden || out["code"] != access.CodePolicyDenied {
		t.Errorf("no policy: %d %v", code, out)
	}
	refusals := 0
	for _, ev := range f.events(audit.SessionConnect) {
		if ev.Outcome == audit.Failure {
			refusals++
		}
	}
	if refusals != 3 {
		t.Errorf("refusals audited: %d, want 3", refusals)
	}
	// Nothing configured: the reason is named.
	f.h.Domain = func() string { return "" }
	if code, out := f.launch(`{"app":"wiki","state":"` + state + `","next":"/"}`); code != http.StatusConflict || out["code"] != "apps_not_ready" {
		t.Errorf("no domain: %d %v", code, out)
	}
	if f.h.URL(nil, "wiki") != "" {
		t.Error("an address is given with no domain")
	}
	f.h.Domain = func() string { return "apps.test" }
	if got := f.h.URL(nil, "wiki"); got != "https://wiki.apps.test/" {
		t.Errorf("URL = %q", got)
	}
	f.h.PublicURL = "https://gw.test:8443"
	if got := f.h.URL(nil, "wiki"); got != "https://wiki.apps.test:8443/" {
		t.Errorf("URL with a port = %q", got)
	}
}

// TestHosts: only one label under the apps domain is an application host;
// a label nothing is served under is a plain 404, not a trip to the console.
func TestHosts(t *testing.T) {
	f := newFixture(t)
	for host, want := range map[string]bool{"wiki.apps.test": true, "Wiki.Apps.Test:8443": true, "apps.test": false, "a.b.apps.test": false, "wiki.apps.test.evil": false, "gw.test": false, "-x.apps.test": false} {
		if got := f.h.Serves(host); got != want {
			t.Errorf("Serves(%q) = %v", host, got)
		}
	}
	if rr := f.app(http.MethodGet, "http://nothing.apps.test/", nil); rr.Code != http.StatusNotFound || rr.Header().Get("Location") != "" {
		t.Errorf("unknown label: %d %q", rr.Code, rr.Header().Get("Location"))
	}
	if rr := f.app(http.MethodGet, "http://a.b.apps.test/", nil); rr.Code != http.StatusNotFound {
		t.Errorf("two labels: %d", rr.Code)
	}
	if rr := f.app(http.MethodGet, "http://wiki.apps.test/_zanskar/anything", nil); rr.Code != http.StatusNotFound {
		t.Errorf("reserved path: %d", rr.Code)
	}
	// Configuration that went away after enrolment: the reason, never a
	// redirect to nowhere that would loop back.
	f.h.PublicURL = ""
	rr := f.app(http.MethodGet, "http://wiki.apps.test/", nil)
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Location") != "" || !strings.Contains(rr.Body.String(), "ZANSKAR_PUBLIC_URL") {
		t.Errorf("without the public URL: %d %q", rr.Code, rr.Header().Get("Location"))
	}
}

// TestLimitsAndSweep: the policy's idle and maximum limits, the sign-in's
// end and a disabled application end the session on the next request, or on
// the sweep when no request comes; a sign-out ends it at once.
func TestLimitsAndSweep(t *testing.T) {
	f := newFixture(t)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := f.db.ExecContext(f.ctx, f.db.Rebind(q), args...); err != nil {
			t.Fatal(err)
		}
	}
	// Idle: the row says nothing happened for twenty minutes.
	appCookie, sid := f.open("/")
	exec(`UPDATE app_sessions SET last_seen_at = ? WHERE session_id = ?`, store.TimeArg(time.Now().Add(-20*time.Minute)), sid)
	if rr := f.app(http.MethodGet, "http://wiki.apps.test/", nil, appCookie); rr.Code != http.StatusFound {
		t.Errorf("idle session served: %d", rr.Code)
	}
	if s := f.waitEnded(sid); s.EndReason != session.EndIdleTimeout {
		t.Errorf("idle end reason: %q", s.EndReason)
	}
	// Maximum: the sweep finds it with no request.
	appCookie, sid = f.open("/")
	exec(`UPDATE app_sessions SET expires_at = ? WHERE session_id = ?`, store.TimeArg(time.Now().Add(-time.Minute)), sid)
	if n, err := f.h.Sweep(f.ctx); err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if s := f.waitEnded(sid); s.EndReason != session.EndMaxDuration {
		t.Errorf("max end reason: %q", s.EndReason)
	}
	if rr := f.app(http.MethodGet, "http://wiki.apps.test/", nil, appCookie); rr.Code != http.StatusFound {
		t.Errorf("swept session served: %d", rr.Code)
	}
	// The sign-in behind it ends: the application session ends with it.
	appCookie, sid = f.open("/")
	if err := f.sessions.Revoke(f.ctx, f.authSID); err != nil {
		t.Fatal(err)
	}
	if rr := f.app(http.MethodGet, "http://wiki.apps.test/", nil, appCookie); rr.Code != http.StatusFound {
		t.Errorf("session of a revoked sign-in served: %d", rr.Code)
	}
	if s := f.waitEnded(sid); s.EndReason != session.EndUserExit {
		t.Errorf("sign-out end reason: %q", s.EndReason)
	}
	// A new sign-in for the rest.
	tok, sess, err := f.sessions.Create(f.ctx, f.alice.ID, "203.0.113.5", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	f.cookie, f.csrf, f.authSID = &http.Cookie{Name: auth.CookieName, Value: tok}, f.sessions.CSRFToken(sess.ID), sess.ID
	// Sign-out on the application host.
	appCookie, sid = f.open("/")
	rr := f.app(http.MethodGet, "http://wiki.apps.test"+signoutPath, nil, appCookie)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Back to Zanskar") {
		t.Errorf("signout: %d %s", rr.Code, rr.Body)
	}
	if s := f.waitEnded(sid); s.EndReason != session.EndUserExit {
		t.Errorf("signout end reason: %q", s.EndReason)
	}
	// The application is disabled: target_lost, as a host that went away.
	appCookie, sid = f.open("/")
	f.wiki.Status = target.StatusDisabled
	if err := f.h.Targets.Update(f.ctx, f.wiki); err != nil {
		t.Fatal(err)
	}
	if rr := f.app(http.MethodGet, "http://wiki.apps.test/", nil, appCookie); rr.Code != http.StatusNotFound {
		t.Errorf("disabled application served: %d", rr.Code)
	}
	if s := f.waitEnded(sid); s.EndReason != session.EndTargetLost {
		t.Errorf("disabled end reason: %q", s.EndReason)
	}
	if f.h.Registry.Count() != 0 {
		t.Errorf("registry holds %d sessions after all ended", f.h.Registry.Count())
	}
}

// TestResume: after a restart the open sessions are back in the registry,
// so an administrator can still end them.
func TestResume(t *testing.T) {
	f := newFixture(t)
	appCookie, sid := f.open("/")
	h2 := &Handler{Repo: f.h.Repo, Sessions: f.access, Auth: f.sessions, Registry: gateway.NewRegistry(), Audit: f.auditLog, Log: f.h.Log,
		Targets: f.h.Targets, Gate: f.h.Gate, Prober: f.h.Prober, Domain: f.h.Domain, PublicURL: f.h.PublicURL}
	if err := h2.Resume(f.ctx); err != nil {
		t.Fatal(err)
	}
	if live := h2.Registry.List(); len(live) != 1 || live[0].SessionID != sid || live[0].PolicyID != f.policyID {
		t.Fatalf("resumed registry: %+v", live)
	}
	// The row still serves the cookie on the new process.
	req := httptest.NewRequest(http.MethodGet, "http://wiki.apps.test/x", nil)
	req.RemoteAddr = clientAddr
	req.AddCookie(appCookie)
	rr := httptest.NewRecorder()
	h2.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("resumed session: %d %s", rr.Code, rr.Body)
	}
	h2.Registry.TerminateWithCause(sid, gateway.ErrPolicyRevoked)
	if s := f.waitEnded(sid); s.EndReason != session.EndPolicyRevoked {
		t.Errorf("end reason: %q", s.EndReason)
	}
}
