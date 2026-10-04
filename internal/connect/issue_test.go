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
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/access"
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/group"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/ticket"
	"github.com/albatroxxx/zanskar/internal/user"
)

// connectFixture is a gateway with one user, alice, and a target for each
// way a connect request can be refused. Policies grant alice everything
// tagged env=test; targets tagged tier=mfa or tier=jit fall under their own
// policies that require an authenticator or an approved request.
type connectFixture struct {
	ctx      context.Context
	srv      http.Handler
	cookie   *http.Cookie
	csrf     string
	alice    *user.User
	auditLog *audit.Log
	access   *access.Repo
	ids      map[string]string // target name -> id
	mfa      bool              // what MFAEnrolled reports for alice
	h        *Handler
	users    *user.Repo
	sessions *auth.Sessions
}

func newConnectFixture(t *testing.T) *connectFixture {
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
	kek, _ := crypto.NewLocalKEK(bytes.Repeat([]byte{7}, 32))
	ring, err := keyring.Open(ctx, db, kek)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f := &connectFixture{ctx: ctx, ids: map[string]string{}, auditLog: audit.NewLog(db), access: access.NewRepo(db)}

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

	vault := credential.NewVault(db, ring)
	cred := func(c *credential.Credential, s *credential.Secret) string {
		t.Helper()
		if err := vault.Create(ctx, c, s, f.alice.ID); err != nil {
			t.Fatalf("credential %s: %v", c.Name, err)
		}
		return c.ID
	}
	vaulted := cred(&credential.Credential{Name: "svc", Type: credential.TypePassword, Mode: credential.ModeVaulted, Username: "svc"}, &credential.Secret{Password: "pw-123456"})
	typed := cred(&credential.Credential{Name: "own", Type: credential.TypePassword, Mode: credential.ModeUserSupplied}, nil)

	targets := target.NewRepo(db)
	const sshFP = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	add := func(tg *target.Target, probe *target.ProbeResult, trust bool) {
		t.Helper()
		if tg.OSFamily == "" {
			tg.OSFamily = target.Linux
		}
		if err := targets.Create(ctx, tg); err != nil {
			t.Fatalf("target %s: %v", tg.Name, err)
		}
		if probe != nil {
			probe.Address, probe.ResolvedIP = tg.Address, tg.Address
			if _, _, err := targets.RecordProbe(ctx, tg.ID, *probe); err != nil {
				t.Fatal(err)
			}
		}
		if trust {
			if _, err := targets.TrustHostKey(ctx, tg.ID, sshFP); err != nil {
				t.Fatal(err)
			}
		}
		f.ids[tg.Name] = tg.ID
	}
	sshProbe := func() *target.ProbeResult {
		return &target.ProbeResult{Capabilities: []target.Protocol{target.SSH}, SSHHostKey: &target.SSHHostKey{Fingerprint: sshFP, Type: "ssh-ed25519"}}
	}
	test := map[string]string{"env": "test"}
	sshCred := map[target.Protocol]string{target.SSH: vaulted}

	add(&target.Target{Name: "ok", Address: "10.0.0.1", Tags: test, Credentials: sshCred}, sshProbe(), true)
	add(&target.Target{Name: "disabled", Address: "10.0.0.2", Tags: test, Credentials: sshCred, Status: "disabled"}, sshProbe(), true)
	add(&target.Target{Name: "prod", Address: "10.0.0.3", Tags: map[string]string{"env": "prod"}, Credentials: sshCred}, sshProbe(), true)
	add(&target.Target{Name: "untrusted", Address: "10.0.0.4", Tags: test, Credentials: sshCred}, sshProbe(), false)
	add(&target.Target{Name: "nocred", Address: "10.0.0.5", Tags: test}, sshProbe(), true)
	add(&target.Target{Name: "typed", Address: "10.0.0.6", Tags: test, Credentials: map[target.Protocol]string{target.SSH: typed}}, sshProbe(), true)
	add(&target.Target{Name: "win-unpinned", Address: "10.0.0.7", OSFamily: target.Windows, Tags: test,
		Credentials: map[target.Protocol]string{target.RDP: vaulted, target.WinRM: vaulted}}, nil, false)
	add(&target.Target{Name: "win-http", Address: "10.0.0.8", OSFamily: target.Windows, Tags: test,
		Ports: map[target.Protocol]int{target.WinRM: 5985}, Credentials: map[target.Protocol]string{target.WinRM: vaulted}}, nil, false)
	add(&target.Target{Name: "plainhost", Address: "10.0.0.9", Tags: test, Credentials: map[target.Protocol]string{target.Database: vaulted}}, nil, false)
	add(&target.Target{Name: "mfa-box", Address: "10.0.0.10", Tags: map[string]string{"tier": "mfa"}, Credentials: sshCred}, sshProbe(), true)
	add(&target.Target{Name: "jit-box", Address: "10.0.0.11", Tags: map[string]string{"tier": "jit"}, Credentials: sshCred}, sshProbe(), true)

	policies := policy.NewRepo(db)
	pol := func(p *policy.Policy) {
		t.Helper()
		p.GroupID, p.Enabled, p.IdleTimeoutMinutes = g.ID, true, 15
		if err := policies.Create(ctx, p); err != nil {
			t.Fatalf("policy %s: %v", p.Name, err)
		}
	}
	pol(&policy.Policy{Name: "test-all", Selector: policy.Selector{Tags: test}, Protocols: []string{"ssh", "rdp", "winrm", "database"}})
	pol(&policy.Policy{Name: "mfa", Selector: policy.Selector{Tags: map[string]string{"tier": "mfa"}}, Protocols: []string{"ssh"}, RequireMFA: true})
	pol(&policy.Policy{Name: "jit", Selector: policy.Selector{Tags: map[string]string{"tier": "jit"}}, Protocols: []string{"ssh"}, RequireApproval: true})

	sessions := auth.NewSessions(db, bytes.Repeat([]byte{2}, 32), false)
	tok, sess, err := sessions.Create(ctx, f.alice.ID, "203.0.113.5", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	f.cookie, f.csrf = &http.Cookie{Name: auth.CookieName, Value: tok}, sessions.CSRFToken(sess.ID)

	h := &Handler{Targets: targets, Policies: policies, Access: f.access, Vault: vault, Sessions: session.NewRepo(db),
		Tickets: ticket.NewStore(), Audit: f.auditLog, Log: log,
		GuacdAddr:   func() string { return "127.0.0.1:4822" },
		MFAEnrolled: func(context.Context, string) (bool, error) { return f.mfa, nil }}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	f.srv = mw.Authenticate(mw.CSRF(mux))
	f.h, f.users, f.sessions = h, users, sessions
	return f
}

// signIn creates a plain user and returns their session cookie and CSRF token.
func (f *connectFixture) signIn(t *testing.T, username string) (*http.Cookie, string) {
	t.Helper()
	u := &user.User{Username: username, DisplayName: username, Roles: []user.Role{user.RoleUser}}
	if err := f.users.Create(f.ctx, u); err != nil {
		t.Fatal(err)
	}
	tok, sess, err := f.sessions.Create(f.ctx, u.ID, "203.0.113.6", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: auth.CookieName, Value: tok}, f.sessions.CSRFToken(sess.ID)
}

// do sends a request as the holder of cookie.
func (f *connectFixture) do(method, path, contentType string, body io.Reader, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("X-CSRF-Token", csrf)
	req.RemoteAddr = "203.0.113.5:4000"
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	f.srv.ServeHTTP(rr, req)
	return rr
}

func (f *connectFixture) connect(t *testing.T, body map[string]any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	req := httptest.NewRequest("POST", "/api/v1/connect", &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", f.csrf)
	req.RemoteAddr = "203.0.113.5:4000"
	req.AddCookie(f.cookie)
	rr := httptest.NewRecorder()
	f.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

// lastConnectEvent returns the newest session.connect audit event.
func (f *connectFixture) lastConnectEvent(t *testing.T) audit.Event {
	t.Helper()
	evs, _, err := f.auditLog.List(f.ctx, audit.Filter{Action: "session.connect", Limit: 1})
	if err != nil || len(evs) == 0 {
		t.Fatalf("no session.connect event: %v", err)
	}
	return evs[0]
}

// TestConnectRefusals: every reason a connect request is refused comes back
// as its own code and status, before any ticket exists, and is audited as a
// failed session.connect naming that reason. A refusal that reads as a
// generic error, or one that is not audited, is a regression.
func TestConnectRefusals(t *testing.T) {
	f := newConnectFixture(t)
	cases := []struct {
		name, target, proto string
		extra               map[string]any
		status              int
		code                string
	}{
		{"disabled target", "disabled", "ssh", nil, http.StatusConflict, "target_disabled"},
		{"no policy covers it", "prod", "ssh", nil, http.StatusForbidden, "policy_denied"},
		{"host key not trusted", "untrusted", "ssh", nil, http.StatusConflict, "host_key_untrusted"},
		{"no credential for the protocol", "nocred", "ssh", nil, http.StatusConflict, "no_credential"},
		{"user-supplied credential missing", "typed", "ssh", nil, http.StatusUnprocessableEntity, "credential_required"},
		{"user-supplied credential half filled", "typed", "ssh", map[string]any{"credential": map[string]string{"username": "bob"}}, http.StatusUnprocessableEntity, "credential_required"},
		{"RDP certificate not captured", "win-unpinned", "rdp", nil, http.StatusConflict, "certificate_unpinned"},
		{"WinRM certificate not captured", "win-unpinned", "winrm", nil, http.StatusConflict, "certificate_unpinned"},
		{"WinRM over plain HTTP", "win-http", "winrm", nil, http.StatusConflict, "tls_required"},
		{"database protocol on a host", "plainhost", "database", nil, http.StatusConflict, "not_a_database"},
		{"policy requires an authenticator", "mfa-box", "ssh", nil, http.StatusForbidden, "mfa_required_by_policy"},
		{"policy requires an approved request", "jit-box", "ssh", nil, http.StatusForbidden, "approval_required"},
		{"unknown target", "", "ssh", map[string]any{"target_id": "no-such-target"}, http.StatusNotFound, "not_found"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := map[string]any{"target_id": f.ids[c.target], "protocol": c.proto}
			for k, v := range c.extra {
				body[k] = v
			}
			status, out := f.connect(t, body)
			if status != c.status || out["code"] != c.code {
				t.Fatalf("got %d %v, want %d %s", status, out, c.status, c.code)
			}
			if out["ticket"] != nil {
				t.Fatal("a refusal must not carry a ticket")
			}
			ev := f.lastConnectEvent(t)
			var d map[string]any
			_ = json.Unmarshal(ev.Details, &d)
			if ev.Outcome != audit.Failure || d["reason"] != c.code || ev.ActorUserID != f.alice.ID {
				t.Fatalf("audit: outcome %s reason %v actor %s, want failure %s by alice", ev.Outcome, d["reason"], ev.ActorUserID, c.code)
			}
		})
	}
}

// TestConnectRejectsUnknownProtocol: a protocol the gateway does not know is
// a malformed request, not a refusal to audit.
func TestConnectRejectsUnknownProtocol(t *testing.T) {
	f := newConnectFixture(t)
	if status, out := f.connect(t, map[string]any{"target_id": f.ids["ok"], "protocol": "telnet"}); status != http.StatusBadRequest {
		t.Fatalf("got %d %v, want 400", status, out)
	}
}

// TestConnectIssuesTickets: the allowed paths end in a ticket and a
// successful session.connect, including the two gates that a refusal test
// alone cannot prove open: an enrolled authenticator, and an approved,
// unexpired request.
func TestConnectIssuesTickets(t *testing.T) {
	f := newConnectFixture(t)
	issued := func(t *testing.T, body map[string]any) {
		t.Helper()
		status, out := f.connect(t, body)
		if status != http.StatusOK || out["ticket"] == "" || out["ticket"] == nil {
			t.Fatalf("got %d %v, want a ticket", status, out)
		}
		if ev := f.lastConnectEvent(t); ev.Outcome != audit.Success {
			t.Fatalf("audit outcome %s, want success", ev.Outcome)
		}
	}

	t.Run("vaulted credential", func(t *testing.T) {
		issued(t, map[string]any{"target_id": f.ids["ok"], "protocol": "ssh"})
	})
	t.Run("user-supplied credential", func(t *testing.T) {
		issued(t, map[string]any{"target_id": f.ids["typed"], "protocol": "ssh", "credential": map[string]string{"username": "bob", "password": "secret"}})
	})
	t.Run("authenticator enrolled", func(t *testing.T) {
		f.mfa = true
		t.Cleanup(func() { f.mfa = false })
		issued(t, map[string]any{"target_id": f.ids["mfa-box"], "protocol": "ssh"})
	})
	t.Run("approved request", func(t *testing.T) {
		req := &access.Request{UserID: f.alice.ID, TargetID: f.ids["jit-box"], Protocol: "ssh", Reason: "incident", RequestedMinutes: 30}
		if err := f.access.Create(f.ctx, req); err != nil {
			t.Fatal(err)
		}
		until := time.Now().Add(30 * time.Minute)
		if _, err := f.access.Decide(f.ctx, req.ID, f.alice.ID, access.StatusApproved, "ok", &until, 30); err != nil {
			t.Fatal(err)
		}
		issued(t, map[string]any{"target_id": f.ids["jit-box"], "protocol": "ssh"})
	})
}
