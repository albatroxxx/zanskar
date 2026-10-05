// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// fakeMFA accepts "123456" for users it was told are enrolled.
type fakeMFA struct{ enrolled map[string]bool }

func (f fakeMFA) Enrolled(_ context.Context, id string) (bool, error) { return f.enrolled[id], nil }

func (f fakeMFA) Verify(_ context.Context, id, code string) (bool, error) {
	switch {
	case !f.enrolled[id]:
		return false, auth.ErrTOTPNotEnrolled
	case code == "123456":
		return false, nil
	case code == "RECOVERY-1":
		return true, nil
	}
	return false, auth.ErrTOTPBadCode
}

type env struct {
	t       *testing.T
	srv     http.Handler
	h       *Handler
	clock   *time.Time
	mu      sync.Mutex
	calls   []string
	admin   *http.Cookie
	csrf    string
	plain   *http.Cookie
	pcsrf   string
	nomfa   *http.Cookie
	nocsrf  string
	auditDB *audit.Log
}

// newEnv builds the command line over a router whose API routes are fakes
// with canned replies, guarded like the real ones.
func newEnv(t *testing.T) *env {
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
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{7}, 32), false)
	now := time.Now()
	e := &env{t: t, clock: &now, auditDB: audit.NewLog(db)}
	mfa := fakeMFA{enrolled: map[string]bool{}}
	e.h = &Handler{Sessions: sessions, MFA: mfa, Audit: e.auditDB, Log: log, now: func() time.Time { return *e.clock }}
	mux := http.NewServeMux()
	e.h.Register(mux)
	e.fakeAPI(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	e.srv = mw.Authenticate(mw.CSRF(mux))
	login := func(name string, role user.Role, enrolled bool) (*http.Cookie, string) {
		u := &user.User{Username: name, DisplayName: name, Roles: []user.Role{role}}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		mfa.enrolled[u.ID] = enrolled
		tok, sess, err := sessions.Create(ctx, u.ID, "203.0.113.9", "test", true)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: auth.CookieName, Value: tok}, sessions.CSRFToken(sess.ID)
	}
	e.admin, e.csrf = login("root", user.RoleAdmin, true)
	e.plain, e.pcsrf = login("alice", user.RoleUser, true)
	e.nomfa, e.nocsrf = login("sso-admin", user.RoleAdmin, false)
	return e
}

const sessID = "3f9a1c20aaaaaaaaaaaaaaaaaaaaaaaa"

func (e *env) fakeAPI(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	reply := func(route string, status int, body string) {
		mux.Handle(route, admin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e.mu.Lock()
			e.calls = append(e.calls, r.Method+" "+r.URL.Path)
			e.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		})))
	}
	reply("GET /api/v1/sessions", 200, `{"items":[{"id":"`+sessID+`","username":"alice","target_name":"web-01","protocol":"ssh","client_ip":"198.51.100.4","started_at":"2026-10-05T09:02:00Z"},
		{"id":"8b20e4ffbbbbbbbbbbbbbbbbbbbbbbbb","username":"carol","target_name":"billing-db","protocol":"database","started_at":"2026-10-05T08:51:00Z","ended_at":"2026-10-05T09:30:00Z","end_reason":"closed"},
		{"id":"8b20e4ffcccccccccccccccccccccccc","username":"dave","asg_name":"web-fleet","protocol":"winrm","started_at":"2026-10-05T08:00:00Z"}]}`)
	reply("POST /api/v1/sessions/{id}/terminate", 200, `{}`)
	reply("GET /api/v1/access-requests", 200, `{"items":[{"id":"9c1d2e3f0000000000000000000000aa","username":"alice","target_name":"orders-db","protocol":"database","requested_minutes":60,"status":"pending","reason":"INC-4821"}]}`)
	for _, v := range []string{"approve", "deny", "revoke"} {
		reply("POST /api/v1/access-requests/{id}/"+v, 200, `{}`)
	}
	reply("GET /api/v1/targets", 200, `{"items":[{"id":"t1","name":"web-01","address":"10.0.0.5","os_family":"linux","host_key_status":"trusted","tags":{"env":"prod"}},{"id":"t2","name":"orders-db","address":"db.internal","os_family":"linux","engine":"postgres","tags":{"env":"staging"}}]}`)
	reply("POST /api/v1/targets/{id}/probe", 200, `{"host_key_fingerprint":"SHA256:abc","capabilities":["ssh"]}`)
	reply("GET /api/v1/access-policies", 200, `{"items":[{"id":"p1","name":"prod-db-jit","protocols":["database"],"target_selector":{"tags":{"role":"db"}},"require_approval":true,"enabled":true,"max_session_minutes":60,"idle_timeout_minutes":10},{"id":"p2","name":"old","enabled":false}]}`)
	reply("GET /api/v1/autoscaling-groups", 200, `{"items":[{"id":"g1","name":"web-fleet","provider":"aws","region":"eu-west-2","external_name":"web-asg","os_family":"linux","status":"ok","last_synced_at":"2026-10-05T09:00:00Z"}]}`)
	reply("POST /api/v1/autoscaling-groups/{id}/sync", 200, `{}`)
	reply("POST /api/v1/admin/storage/test", 200, `{"ok":true}`)
	reply("GET /api/v1/admin/storage", 200, `{"source":"s3","counts":{"s3":4},"move":{"running":true,"moved":2,"failed":1,"total":4}}`)
	reply("GET /api/v1/admin/system/status", 200, `{"version":"1.2.2","uptime_seconds":273600,"live_sessions":2,"draining":true}`)
	reply("POST /api/v1/admin/system/restart", 202, `{}`)
	reply("DELETE /api/v1/admin/system/restart", 200, `{}`)
	reply("GET /api/v1/audit/verify", 200, `{"intact":false,"checked":12,"broken":{"id":7,"reason":"hash mismatch"}}`)
	reply("GET /api/v1/admin/logs", 200, `{"items":[{"time":"2026-10-05T09:00:00Z","level":"WARN","msg":"slow probe","attrs":{"target":"web-01"}},{"time":"2026-10-05T09:00:01Z","level":"ERROR","msg":"boom"},{"time":"2026-10-05T09:00:02Z","level":"DEBUG","msg":"tick"}]}`)
	reply("GET /api/v1/admin/tls", 200, `{"mode":"managed","subject":"CN=gw","hosts":["gw.example.test"],"not_after":"2027-01-01T00:00:00Z"}`)
	reply("GET /api/v1/users", 200, `{"items":[{"id":"u1","username":"alice","display_name":"Alice","roles":["user"],"status":"active"}]}`)
	reply("DELETE /api/v1/users/{id}/mfa", 204, ``)
	reply("DELETE /api/v1/users/{id}/sessions", 200, `{"revoked":2}`)
	reply("GET /api/v1/audit/events", 200, `{"items":[{"id":5,"ts":"2026-10-05T09:00:00Z","action":"system.start","object_type":"system","outcome":"success"}]}`)
	reply("GET /api/v1/version", 500, `{"code":"internal","message":"Internal error"}`)
	reply("GET /api/v1/admin/settings", 403, `{"code":"forbidden","message":"insufficient role"}`)
}

func (e *env) post(path string, body any, cookie *http.Cookie, csrf string) (int, map[string]any) {
	e.t.Helper()
	b, _ := json.Marshal(body)
	method := http.MethodPost
	if body == nil {
		method = http.MethodGet
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.RemoteAddr = "203.0.113.9:4321"
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func (e *env) unlock() {
	e.t.Helper()
	if code, out := e.post("/api/v1/admin/cli/unlock", map[string]string{"code": "123456"}, e.admin, e.csrf); code != 200 {
		e.t.Fatalf("unlock: %d %v", code, out)
	}
}

func (e *env) run(line, confirm string) (string, string) {
	e.t.Helper()
	code, out := e.post("/api/v1/admin/cli", map[string]string{"line": line, "confirm": confirm}, e.admin, e.csrf)
	if code != 200 {
		e.t.Fatalf("%q: HTTP %d %v", line, code, out)
	}
	var text []string
	for _, l := range out["lines"].([]any) {
		text = append(text, l.(map[string]any)["text"].(string))
	}
	return out["status"].(string), strings.Join(text, "\n")
}

// TestLockedUntilAFreshCode: the command line opens only after a code, stays
// open while used, and closes after the idle time.
func TestLockedUntilAFreshCode(t *testing.T) {
	e := newEnv(t)
	if code, out := e.post("/api/v1/admin/cli", nil, e.admin, e.csrf); code != 200 || out["unlocked"] != false || out["mfa_enrolled"] != true {
		t.Fatalf("state before a code: %d %v", code, out)
	}
	if code, out := e.post("/api/v1/admin/cli", map[string]string{"line": "status"}, e.admin, e.csrf); code != 403 || out["code"] != "cli_locked" {
		t.Fatalf("a line before a code: %d %v", code, out)
	}
	e.unlock()
	if status, _ := e.run("sessions", ""); status != "ok" {
		t.Fatalf("after the code: %s", status)
	}
	*e.clock = e.clock.Add(freshFor - time.Minute)
	if status, _ := e.run("sessions", ""); status != "ok" {
		t.Fatalf("within the idle time: %s", status)
	}
	*e.clock = e.clock.Add(freshFor + time.Second)
	if code, _ := e.post("/api/v1/admin/cli", map[string]string{"line": "sessions"}, e.admin, e.csrf); code != 403 {
		t.Fatalf("after the idle time: %d, want 403", code)
	}
	// Not for other roles at all.
	if code, _ := e.post("/api/v1/admin/cli", map[string]string{"line": "help"}, e.plain, e.pcsrf); code != 403 {
		t.Fatalf("a non-admin: %d, want 403", code)
	}
}

// TestUnlockGuards: wrong codes close the command line for a while, a
// recovery code works and is audited, and an account with no authenticator
// is told to enrol one.
func TestUnlockGuards(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < maxFails; i++ {
		if code, _ := e.post("/api/v1/admin/cli/unlock", map[string]string{"code": "999999"}, e.admin, e.csrf); code != 422 {
			t.Fatalf("wrong code %d: %d", i, code)
		}
	}
	if code, out := e.post("/api/v1/admin/cli/unlock", map[string]string{"code": "123456"}, e.admin, e.csrf); code != 429 {
		t.Fatalf("right code while closed: %d %v", code, out)
	}
	*e.clock = e.clock.Add(lockFor + time.Second)
	if code, _ := e.post("/api/v1/admin/cli/unlock", map[string]string{"code": "RECOVERY-1"}, e.admin, e.csrf); code != 200 {
		t.Fatalf("recovery code after the lock: %d", code)
	}
	if code, out := e.post("/api/v1/admin/cli/unlock", map[string]string{"code": "123456"}, e.nomfa, e.nocsrf); code != 409 || out["code"] != "mfa_not_enrolled" {
		t.Fatalf("no authenticator: %d %v", code, out)
	}
	if code, out := e.post("/api/v1/admin/cli", nil, e.nomfa, e.nocsrf); code != 200 || out["unlocked"] != false {
		t.Fatalf("state with no authenticator: %d %v", code, out)
	}
}

// TestCommandsOverTheAPI runs the commands the end-to-end test cannot reach
// without live sessions, requests or a cloud, and checks the routes called.
func TestCommandsOverTheAPI(t *testing.T) {
	e := newEnv(t)
	e.unlock()
	cases := []struct {
		line, confirm, status string
		want                  []string
	}{
		{"sessions --live --last 5", "", "ok", []string{"3f9a1c20", "alice", "SSH", "billing-db", "database", "ended", "web-fleet", "WinRM"}},
		{"sessions --target web-01", "", "ok", []string{"ID"}},
		{"session show 3f9a1c", "", "ok", []string{sessID, "198.51.100.4"}},
		{"session show 8b20e4", "", "error", []string{"more than one session"}},
		{"session show 3f9a", "", "error", []string{"at least the first 6"}},
		{"session show ffffff", "", "error", []string{"No session with id"}},
		{"session terminate 8b20e4ffbbbb", "", "error", []string{"already ended"}},
		{"session terminate 3f9a1c20", "", "confirm", []string{"ends alice's SSH session to web-01", "Type alice"}},
		{"session terminate 3f9a1c20", "alice", "ok", []string{"Terminated"}},
		{"requests --pending", "", "ok", []string{"9c1d2e3f", "orders-db", "60m", "INC-4821"}},
		{"request approve 9c1d2e3f ok for the incident", "", "ok", []string{"Approved"}},
		{"request deny 9c1d2e3f", "", "ok", []string{"Denied"}},
		{"request revoke 9c1d2e3f", "", "confirm", []string{"withdraws alice's access to orders-db"}},
		{"request revoke 9c1d2e3f", "alice", "ok", []string{"Revoked"}},
		{"targets --search web", "", "ok", []string{"web-01", "postgres"}},
		{"targets --tag env", "", "error", []string{"key=value"}},
		{"target probe web-01", "", "ok", []string{"Probed web-01", "SHA256:abc", "Trust is unchanged"}},
		{"policies", "", "ok", []string{"prod-db-jit", "approval", "off"}},
		{"policy show prod-db-jit", "", "ok", []string{"60 min", "role"}},
		{"asgs", "", "ok", []string{"web-fleet", "aws eu-west-2"}},
		{"asg sync web-fleet", "", "ok", []string{"Synced web-fleet"}},
		{"storage", "", "ok", []string{"running: 2 of 4 moved, 1 failed"}},
		{"storage test", "", "ok", []string{"accepted a test object"}},
		{"status", "", "ok", []string{"up 3d 4h", "restarting once live sessions end", "CHAIN BROKEN at event 7"}},
		{"audit verify", "", "ok", []string{"Chain broken at event 7: hash mismatch", "host-only"}},
		{"logs --level warn --search probe --last 3", "", "ok", []string{"WARN  slow probe  target=web-01", "ERROR boom", "tick"}},
		{"logs --last 0", "", "error", []string{"--last takes a number"}},
		{"tls", "", "ok", []string{"managed", "CN=gw", "gw.example.test"}},
		{"restart --wait 15", "", "confirm", []string{"once the 2 live sessions end, or after 15 minutes"}},
		{"restart --wait 15", "restart", "ok", []string{"Restart started"}},
		{"restart --wait 0", "", "confirm", []string{"restarts the gateway now. 2 live sessions end"}},
		{"restart", "", "confirm", []string{"or after 15 minutes"}},
		{"restart --wait 999", "", "error", []string{"--wait takes minutes"}},
		{"restart cancel", "", "ok", []string{"Restart cancelled"}},
		{"user reset-mfa alice", "", "confirm", []string{"removes alice's authenticator"}},
		{"user reset-mfa alice", "alice", "ok", []string{"Authenticator removed for alice"}},
		{"user signout alice", "", "confirm", []string{"ends every console sign-in alice has"}},
		{"user signout alice", "alice", "ok", []string{"signed out everywhere"}},
		{"events --user alice --action system.start", "", "ok", []string{"system.start", "system"}},
		{"version", "", "error", []string{"Internal error"}},
		{"help nosuch", "", "error", []string{`No command "nosuch"`}},
		{"help sessions", "", "ok", []string{"--live", "only sessions still open"}},
		{"sessions --live --live", "", "error", []string{"given twice"}},
		{"sessions --live=yes", "", "error", []string{"takes no value"}},
		{"sessions --user", "", "error", []string{"needs a value"}},
		{"session show", "", "error", []string{"Usage: session show <id>"}},
		{"sessions extra", "", "error", []string{"Usage: sessions"}},
		{"setting set", "", "error", []string{"Usage: setting set <key> <value>"}},
		{`"unclosed`, "", "error", []string{"not closed"}},
		{"settings", "", "error", []string{"Not allowed: insufficient role"}},
	}
	for _, c := range cases {
		status, text := e.run(c.line, c.confirm)
		if status != c.status {
			t.Errorf("%q: status %s, want %s\n%s", c.line, status, c.status, text)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(text, w) {
				t.Errorf("%q: output lacks %q\n%s", c.line, w, text)
			}
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	joined := strings.Join(e.calls, "\n")
	for _, want := range []string{
		"POST /api/v1/sessions/" + sessID + "/terminate",
		"POST /api/v1/access-requests/9c1d2e3f0000000000000000000000aa/approve",
		"POST /api/v1/access-requests/9c1d2e3f0000000000000000000000aa/revoke",
		"POST /api/v1/targets/t1/probe",
		"POST /api/v1/autoscaling-groups/g1/sync",
		"DELETE /api/v1/users/u1/mfa",
		"DELETE /api/v1/users/u1/sessions",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("no %s among the calls:\n%s", want, joined)
		}
	}
}

// TestConfirmationIsSingleUseAndExpires: an answer only counts for the line
// that was prompted, once, within the time allowed.
func TestConfirmationIsSingleUseAndExpires(t *testing.T) {
	e := newEnv(t)
	e.unlock()
	if status, _ := e.run("user signout alice", "alice"); status != "error" {
		t.Fatalf("an answer with no prompt: %s", status)
	}
	e.run("user signout alice", "")
	if status, _ := e.run("user reset-mfa alice", "alice"); status != "error" {
		t.Fatalf("an answer for a different line: %s", status)
	}
	e.run("user signout alice", "")
	*e.clock = e.clock.Add(confirmFor + time.Second)
	e.unlock()
	if status, _ := e.run("user signout alice", "alice"); status != "error" {
		t.Fatalf("an answer after the prompt expired: %s", status)
	}
}

// TestRateLimit: a sign-in gets perMinute lines a minute.
func TestRateLimit(t *testing.T) {
	e := newEnv(t)
	e.unlock()
	for i := 0; i < perMinute; i++ {
		e.run("help", "")
	}
	if code, out := e.post("/api/v1/admin/cli", map[string]string{"line": "help"}, e.admin, e.csrf); code != 429 {
		t.Fatalf("line %d: %d %v", perMinute+1, code, out)
	}
	*e.clock = e.clock.Add(time.Minute)
	if status, _ := e.run("help", ""); status != "ok" {
		t.Fatalf("after a minute: %s", status)
	}
}

func TestTokenize(t *testing.T) {
	cases := []struct {
		in   string
		want []string
		err  string
	}{
		{"users", []string{"users"}, ""},
		{"  request approve  9c1d   'ok for now' ", []string{"request", "approve", "9c1d", "ok for now"}, ""},
		{`setting set login.banner "Use is monitored; $5 fine"`, []string{"setting", "set", "login.banner", "Use is monitored; $5 fine"}, ""},
		{"a\tb", []string{"a", "b"}, ""},
		{"", nil, "empty"},
		{"users; reboot", nil, "not a shell"},
		{"echo $HOME", nil, "not a shell"},
		{"users > /tmp/x", nil, "not a shell"},
		{"a\x00b", nil, "control character"},
		{strings.Repeat("a ", maxTokens+1), nil, "more than"},
		{strings.Repeat("a", maxLine+1), nil, "longer than"},
	}
	for _, c := range cases {
		got, err := tokenize(c.in)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("tokenize(%q) error = %v, want %q", c.in, err, c.err)
			}
			continue
		}
		if err != nil || strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("tokenize(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

// TestCommandTable: every command has what help and the reference need, and
// names are unique.
func TestCommandTable(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range commands() {
		if seen[c.name] {
			t.Errorf("duplicate command %q", c.name)
		}
		seen[c.name] = true
		if c.group == "" || c.summary == "" || c.example == "" || c.exec == nil {
			t.Errorf("%q is missing a group, summary, example or exec", c.name)
		}
		if !strings.HasPrefix(c.example, c.name) {
			t.Errorf("%q: example %q does not start with the command", c.name, c.example)
		}
	}
}

func TestFormat(t *testing.T) {
	if got := span(26*time.Hour + 4*time.Minute); got != "1d 2h" {
		t.Errorf("span = %q", got)
	}
	if got := span(90 * time.Minute); got != "1h 30m" {
		t.Errorf("span = %q", got)
	}
	if got := span(40 * time.Second); got != "40s" {
		t.Errorf("span = %q", got)
	}
	o := &out{}
	o.table([]string{"A", "B"}, [][]string{{strings.Repeat("x", 60), "multi\nline"}})
	if !strings.Contains(o.lines[1].Text, "…") || !strings.Contains(o.lines[1].Text, "multi line") {
		t.Errorf("table row = %q", o.lines[1].Text)
	}
	if got := str(obj{"n": 1.5, "b": false, "x": struct{}{}}, "n"); got != "1.5" {
		t.Errorf("str float = %q", got)
	}
	if got := when(obj{"t": "not a time"}, "t"); got != "not a time" {
		t.Errorf("when = %q", got)
	}
}

func FuzzTokenize(f *testing.F) {
	for _, s := range []string{"users", `a "b c" 'd'`, "x;y", "\x00", `"`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		toks, err := tokenize(s)
		if err != nil {
			return
		}
		if len(toks) == 0 || len(toks) > maxTokens {
			t.Fatalf("tokenize(%q) = %d tokens", s, len(toks))
		}
		for _, tok := range toks {
			if strings.ContainsAny(tok, "\x00\n\r") {
				t.Fatalf("tokenize(%q) kept a control character in %q", s, tok)
			}
		}
	})
}

// TestReferenceIsCurrent: docs/console-cli.md is what the command table
// says; regenerate it with go run ./hack/gen-cli-docs > docs/console-cli.md.
func TestReferenceIsCurrent(t *testing.T) {
	raw, err := os.ReadFile("../../docs/console-cli.md")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != Reference() {
		t.Fatal("docs/console-cli.md is out of date: run go run ./hack/gen-cli-docs > docs/console-cli.md")
	}
}
