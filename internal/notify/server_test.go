// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
)

// TestEmailServerAPI (ADR 0039, amended 2026-11-03, later): the mail
// server is set once through the API, read back without its password, kept
// when the password field is left empty, refused without a password for an
// account, tested with one message, and forgotten; each is audited.
func TestEmailServerAPI(t *testing.T) {
	port, got := fakeSMTP(t)
	e := newEnv(t, nil)
	if code, _, raw := e.do(t, "GET", "/api/v1/admin/notifications/email-server", nil); code != 200 || strings.TrimSpace(raw) != "null" {
		t.Fatalf("none yet: %d %s", code, raw)
	}
	for _, c := range []struct {
		body map[string]any
		want string
	}{
		{map[string]any{"host": "", "from": "gw@example.com"}, "host:"},
		{map[string]any{"host": "mail.example.com", "port": 70000, "from": "gw@example.com"}, "port:"},
		{map[string]any{"host": "mail.example.com", "from": "not-an-address"}, "from:"},
		{map[string]any{"host": "mail.example.com", "from": "gw@example.com", "username": "svc"}, "password: required"},
	} {
		if code, _, raw := e.do(t, "PUT", "/api/v1/admin/notifications/email-server", c.body); code != 400 || !strings.Contains(raw, c.want) {
			t.Errorf("%v: %d %s, want a refusal mentioning %q", c.body, code, raw, c.want)
		}
	}
	code, out, _ := e.do(t, "PUT", "/api/v1/admin/notifications/email-server", map[string]any{"host": "127.0.0.1", "port": port, "username": "svc", "password": "s3cret", "from": "gw@example.com"})
	if code != 200 || out["host"] != "127.0.0.1" || out["has_password"] != true || out["password"] != nil {
		t.Fatalf("set: %d %v", code, out)
	}
	if evs, _, _ := e.audit.List(context.Background(), audit.Filter{Action: audit.NotifyEmailServerUpdate}); len(evs) != 1 || strings.Contains(string(evs[0].Details), "s3cret") {
		t.Fatalf("set audit: %v", evs)
	}
	// Saved again without a password: the stored one stays.
	if code, out, _ := e.do(t, "PUT", "/api/v1/admin/notifications/email-server", map[string]any{"host": "127.0.0.1", "port": port, "username": "svc", "from": "gw@example.com"}); code != 200 || out["has_password"] != true {
		t.Fatalf("keep: %d %v", code, out)
	}
	s, err := e.repo.Server(context.Background())
	if err != nil || s == nil || s.password != "s3cret" {
		t.Fatalf("kept password: %+v %v", s, err)
	}
	// Without an account, no password is held.
	if code, out, _ := e.do(t, "PUT", "/api/v1/admin/notifications/email-server", map[string]any{"host": "127.0.0.1", "port": port, "from": "gw@example.com"}); code != 200 || out["has_password"] != false {
		t.Fatalf("no account: %d %v", code, out)
	}
	if code, _, raw := e.do(t, "POST", "/api/v1/admin/notifications/email-server/test", map[string]any{"to": "nope"}); code != 400 || !strings.Contains(raw, "to:") {
		t.Fatalf("test to a non-address: %d %s", code, raw)
	}
	if code, _, raw := e.do(t, "POST", "/api/v1/admin/notifications/email-server/test", map[string]any{"to": "me@example.com"}); code != 204 {
		t.Fatalf("test: %d %s", code, raw)
	}
	if msg := got(); !strings.Contains(msg, "To: me@example.com\r\n") || !strings.Contains(msg, "The mail server works") {
		t.Fatalf("the test message:\n%s", msg)
	}
	if evs, _, _ := e.audit.List(context.Background(), audit.Filter{Action: audit.NotifyEmailServerTest}); len(evs) != 1 || evs[0].Outcome != audit.Success {
		t.Fatalf("test audit: %v", evs)
	}
	if code, _, _ := e.do(t, "DELETE", "/api/v1/admin/notifications/email-server", nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _, raw := e.do(t, "GET", "/api/v1/admin/notifications/email-server", nil); code != 200 || strings.TrimSpace(raw) != "null" {
		t.Fatalf("after delete: %d %s", code, raw)
	}
	if code, _, raw := e.do(t, "POST", "/api/v1/admin/notifications/email-server/test", map[string]any{"to": "me@example.com"}); code != 409 || !strings.Contains(raw, "no_mail_server") {
		t.Fatalf("test without a server: %d %s", code, raw)
	}
}

// TestLegacyChannelServerAdopted: an email channel from before the gateway
// had a mail server carries its own; at start the first one's becomes the
// gateway's, password included, and every email channel keeps its
// recipients alone. Until then, such a channel still sends through its own.
func TestLegacyChannelServerAdopted(t *testing.T) {
	port, got := fakeSMTP(t)
	e := newEnv(t, nil)
	ctx := context.Background()
	legacy := &Channel{Name: "old", Kind: KindEmail, Enabled: true, Events: []string{EventDiskFull},
		Config: Config{SMTPHost: "127.0.0.1", SMTPPort: port, SMTPUsername: "svc", From: "gw@example.com", To: []string{"ops@example.com"}}}
	if err := e.repo.Create(ctx, legacy, Secret{SMTPPassword: "p"}); err != nil {
		t.Fatal(err)
	}
	other := &Channel{Name: "other", Kind: KindEmail, Enabled: true, Events: []string{EventDiskFull},
		Config: Config{SMTPHost: "127.0.0.1", SMTPPort: port, From: "x@example.com", To: []string{"sec@example.com"}}}
	if err := e.repo.Create(ctx, other, Secret{}); err != nil {
		t.Fatal(err)
	}
	// Before adoption: a channel's own server serves (the fake takes no AUTH, so the one without an account sends).
	if err := e.notifier.Sender.Send(ctx, other, Message{Kind: "test", Subject: "hi", Text: "hi"}); err != nil {
		t.Fatalf("legacy send: %v", err)
	}
	if !strings.Contains(got(), "From: x@example.com") {
		t.Fatalf("legacy message:\n%s", got())
	}
	adopted, err := e.repo.AdoptServer(ctx)
	if err != nil || adopted == nil || adopted.Host != "127.0.0.1" || adopted.Port != port || adopted.Username != "svc" || adopted.From != "gw@example.com" || adopted.password != "p" {
		t.Fatalf("adopted: %+v %v", adopted, err)
	}
	for _, id := range []string{legacy.ID, other.ID} {
		c, err := e.repo.Get(ctx, id)
		if err != nil || c.Config.SMTPHost != "" || c.Config.From != "" || c.secret.SMTPPassword != "" || len(c.Config.To) != 1 {
			t.Fatalf("channel %s after adoption: %+v %v", id, c.Config, err)
		}
	}
	if again, err := e.repo.AdoptServer(ctx); err != nil || again != nil {
		t.Fatalf("a second start adopts nothing: %+v %v", again, err)
	}
	s, _ := e.repo.Server(ctx)
	if s == nil || !s.HasPassword {
		t.Fatalf("the server after adoption: %+v", s)
	}
}

// TestEmailChannelNeedsTheServer: with no mail server and nothing of its
// own, an email channel's delivery fails with words that say where to set
// one.
func TestEmailChannelNeedsTheServer(t *testing.T) {
	e := newEnv(t, nil)
	c := &Channel{Name: "mail", Kind: KindEmail, Enabled: true, Config: Config{To: []string{"ops@example.com"}}}
	err := e.notifier.Sender.Send(context.Background(), c, Message{Kind: "test", Subject: "hi", Text: "hi"})
	if err == nil || !strings.Contains(err.Error(), "no mail server is set") {
		t.Fatalf("send without a server: %v", err)
	}
}
