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

// TestCertificateAuthorityPrincipalAllowlist: a CA credential limited to
// named login users refuses a connect for anyone else before a ticket
// exists (ADR 0022), and the refusal is audited like every other one. With
// the allowlist empty, or naming the user, a ticket is issued.
func TestCertificateAuthorityPrincipalAllowlist(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	kek, _ := crypto.NewLocalKEK(bytes.Repeat([]byte{3}, 32))
	ring, _ := keyring.Open(ctx, db, kek)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	u := &user.User{Username: "alice", DisplayName: "Alice", Roles: []user.Role{user.RoleUser}}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	groups := group.NewRepo(db)
	g := &group.Group{Name: "ops"}
	if err := groups.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := groups.AddMember(ctx, g.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	vault := credential.NewVault(db, ring)
	caPEM, err := credential.GenerateSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	// No fixed username: each user logs in as their own Zanskar username.
	cred := &credential.Credential{Name: "ca", Type: credential.TypeSSHCA, Mode: credential.ModeVaulted, CertificatePrincipals: []string{"deploy", "ops"}}
	if err := vault.Create(ctx, cred, &credential.Secret{PrivateKey: caPEM}, u.ID); err != nil {
		t.Fatal(err)
	}
	targets := target.NewRepo(db)
	tg := &target.Target{Name: "web-1", Address: "10.0.0.7", OSFamily: target.Linux, Tags: map[string]string{"env": "test"},
		Credentials: map[target.Protocol]string{target.SSH: cred.ID}}
	if err := targets.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	const fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, _, err := targets.RecordProbe(ctx, tg.ID, target.ProbeResult{Address: tg.Address, ResolvedIP: tg.Address, Capabilities: []target.Protocol{target.SSH},
		SSHHostKey: &target.SSHHostKey{Fingerprint: fp, Type: "ssh-ed25519"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := targets.TrustHostKey(ctx, tg.ID, fp); err != nil {
		t.Fatal(err)
	}
	pol := &policy.Policy{Name: "ops-web", GroupID: g.ID, Enabled: true, Selector: policy.Selector{Targets: []string{tg.ID}}, Protocols: []string{"ssh"}, IdleTimeoutMinutes: 15}
	if err := policy.NewRepo(db).Create(ctx, pol); err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{1}, 32), false)
	tok, sess, err := sessions.Create(ctx, u.ID, "203.0.113.5", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	auditLog := audit.NewLog(db)
	h := &Handler{Targets: targets, Policies: policy.NewRepo(db), Vault: vault, Sessions: session.NewRepo(db), Tickets: ticket.NewStore(),
		Audit: auditLog, Log: log, MFAEnrolled: func(context.Context, string) (bool, error) { return true, nil }}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	srv := mw.Authenticate(mw.CSRF(mux))
	connect := func() (int, map[string]any) {
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(map[string]any{"target_id": tg.ID, "protocol": "ssh"})
		req := httptest.NewRequest("POST", "/api/v1/connect", &buf)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", sessions.CSRFToken(sess.ID))
		req.RemoteAddr = "203.0.113.5:4321"
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: tok})
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}

	// alice is not deploy or ops: refused, and audited with the reason.
	code, out := connect()
	if code != http.StatusForbidden || out["code"] != "login_user_not_permitted" {
		t.Fatalf("unlisted login user: got %d %v, want 403 login_user_not_permitted", code, out)
	}
	events, _, err := auditLog.List(ctx, audit.Filter{Action: "session.connect", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Outcome != audit.Failure || !strings.Contains(string(events[0].Details), `"reason":"login_user_not_permitted"`) {
		t.Fatalf("refusal should be audited as a failed session.connect with the reason: %+v", events)
	}

	// Listing alice, or clearing the list, lets the ticket through.
	if _, err := vault.Update(ctx, cred.ID, credential.Metadata{Name: cred.Name, CertificatePrincipals: []string{"deploy", "alice"}}); err != nil {
		t.Fatal(err)
	}
	if code, out = connect(); code != http.StatusOK || out["ticket"] == nil {
		t.Fatalf("listed login user: got %d %v, want a ticket", code, out)
	}
	if _, err := vault.Update(ctx, cred.ID, credential.Metadata{Name: cred.Name}); err != nil {
		t.Fatal(err)
	}
	if code, out = connect(); code != http.StatusOK || out["ticket"] == nil {
		t.Fatalf("empty allowlist: got %d %v, want a ticket", code, out)
	}
	// A fixed username on the credential is what the allowlist is checked
	// against, not the Zanskar username.
	if _, err := vault.Update(ctx, cred.ID, credential.Metadata{Name: cred.Name, Username: "deploy", CertificatePrincipals: []string{"deploy"}}); err != nil {
		t.Fatal(err)
	}
	if code, out = connect(); code != http.StatusOK || out["ticket"] == nil {
		t.Fatalf("fixed username in the allowlist: got %d %v, want a ticket", code, out)
	}
}
