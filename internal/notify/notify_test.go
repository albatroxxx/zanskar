// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/user"
)

// hook is a webhook receiver: it keeps every body and its signature check.
type hook struct {
	mu       sync.Mutex
	bodies   []map[string]any
	verified []bool
	key      []byte
	status   int
	srv      *httptest.Server
}

func newHook(t *testing.T) *hook {
	h := &hook{status: 200}
	h.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		defer h.mu.Unlock()
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		h.bodies = append(h.bodies, m)
		want := "sha256=" + audit.Sign(h.key, r.Header.Get("X-Zanskar-Timestamp"), body)
		h.verified = append(h.verified, r.Header.Get("X-Zanskar-Signature") == want)
		w.WriteHeader(h.status)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hook) texts() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, b := range h.bodies {
		out = append(out, b["text"].(string))
	}
	return out
}

// toHook carries every webhook request to the test server, whatever host the
// URL names, as a name a public webhook would have.
type toHook struct{ h *hook }

func (t toHook) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Host = strings.TrimPrefix(t.h.srv.URL, "https://")
	return t.h.srv.Client().Transport.RoundTrip(r)
}

type env struct {
	db       *store.DB
	repo     *Repo
	audit    *audit.Log
	notifier *Notifier
	srv      http.Handler
	cookie   *http.Cookie
	csrf     string
	userCk   *http.Cookie
	userCSRF string
	adminID  string
}

func newEnv(t *testing.T, transport http.RoundTripper) *env {
	t.Helper()
	ctx := context.Background()
	db := storetest.Open(t)
	kek, _ := crypto.NewLocalKEK(bytes.Repeat([]byte{7}, 32))
	ring, err := keyring.Open(ctx, db, kek)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := &env{db: db, repo: NewRepo(db, ring), audit: audit.NewLog(db)}
	names := func(_ context.Context, kind string, ids []string) (map[string]string, error) {
		m := map[string]string{}
		for _, id := range ids {
			m[id] = kind + ":" + id
		}
		return m, nil
	}
	e.notifier = &Notifier{Channels: e.repo, Audit: e.audit, Resolve: names, Base: "https://gw.example.com", Sender: &Sender{Transport: transport, AllowLoopback: true}, Log: log}
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{2}, 32), false)
	mux := http.NewServeMux()
	(&Handler{Channels: e.repo, Notifier: e.notifier, Audit: e.audit, Log: log}).Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	e.srv = mw.Authenticate(mw.CSRF(mux))
	for name, role := range map[string]user.Role{"root": user.RoleAdmin, "alice": user.RoleUser} {
		u := &user.User{Username: name, DisplayName: name, Roles: []user.Role{role}}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		tok, sess, err := sessions.Create(ctx, u.ID, "127.0.0.1", "test", true)
		if err != nil {
			t.Fatal(err)
		}
		if name == "root" {
			e.cookie, e.csrf, e.adminID = &http.Cookie{Name: auth.CookieName, Value: tok}, sessions.CSRFToken(sess.ID), u.ID
		} else {
			e.userCk, e.userCSRF = &http.Cookie{Name: auth.CookieName, Value: tok}, sessions.CSRFToken(sess.ID)
		}
	}
	return e
}

func (e *env) do(t *testing.T, method, path string, body any) (int, map[string]any, string) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrf)
	req.AddCookie(e.cookie)
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out, rr.Body.String()
}

func (e *env) record(t *testing.T, ev audit.Event) {
	t.Helper()
	if _, err := e.audit.Record(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
}

// 2026-11-03, idea 3 (ADR 0039): a channel is told the events it asked for,
// signed, from its creation on, once each, and an incoming-webhook URL, the
// credential, never leaves the gateway's database unsealed.
func TestWebhookChannel(t *testing.T) {
	h := newHook(t)
	e := newEnv(t, toHook{h})
	actor := audit.Actor{UserID: "u-bob", IP: "10.0.0.1"}
	// History before the channel: never sent.
	e.record(t, actor.Event(audit.AccessRequestCreate, "access_request", "old", audit.Success, map[string]any{"target_id": "t0", "protocol": "ssh"}))

	const secretURL = "https://hooks.example.com/services/T000/B000/XXXXSECRET"
	code, out, raw := e.do(t, "POST", "/api/v1/admin/notifications", map[string]any{
		"name": "ops", "kind": "webhook", "events": []string{"access_requested", "provider_failing"}, "webhook_url": secretURL,
	})
	if code != 201 {
		t.Fatalf("create: %d %s", code, raw)
	}
	key, _ := out["signing_key"].(string)
	if len(key) != 64 {
		t.Fatalf("the signing key is shown once at creation: %s", raw)
	}
	h.key = []byte(key)
	id := out["channel"].(map[string]any)["id"].(string)

	// The URL is sealed: neither the list nor the row holds it in clear.
	_, _, list := e.do(t, "GET", "/api/v1/admin/notifications", nil)
	if strings.Contains(list, "XXXXSECRET") || strings.Contains(list, key) || !strings.Contains(list, `"webhook_host":"hooks.example.com"`) {
		t.Fatalf("the list: %s", list)
	}
	var sealed []byte
	if err := e.db.QueryRowContext(context.Background(), e.db.Rebind(`SELECT secret_enc FROM notification_channels WHERE id = ?`), id).Scan(&sealed); err != nil || bytes.Contains(sealed, []byte("XXXXSECRET")) {
		t.Fatalf("the secret is not sealed: %v", err)
	}

	e.record(t, actor.Event(audit.AccessRequestCreate, "access_request", "r1", audit.Success, map[string]any{"target_id": "t1", "protocol": "ssh"}))
	e.record(t, actor.Event(audit.SessionConnect, "target", "t1", audit.Success, nil)) // not asked for
	e.record(t, audit.Actor{IP: "sync"}.Event(audit.IdPSync, "identity_provider", "kc", audit.Failure, map[string]any{"error": "could not reach keycloak"}))
	e.notifier.Pass(context.Background())

	got := h.texts()
	if len(got) != 2 {
		t.Fatalf("sent %d messages, want the request and the provider: %v", len(got), got)
	}
	if got[0] != "user:u-bob asks for SSH access to target:t1. Open it to approve or deny. https://gw.example.com/admin/approvals?request=r1" {
		t.Fatalf("request message: %q", got[0])
	}
	if !strings.HasPrefix(got[1], "Sign-in provider identity_provider:kc failed its sync: could not reach keycloak.") {
		t.Fatalf("provider message: %q", got[1])
	}
	for i, ok := range h.verified {
		if !ok {
			t.Fatalf("message %d's signature does not verify", i)
		}
	}
	// Once each.
	e.notifier.Pass(context.Background())
	if n := len(h.texts()); n != 2 {
		t.Fatalf("a second pass sent again: %d", n)
	}

	// The receiver fails: the event is kept and sent once it answers again.
	h.status = 500
	e.record(t, actor.Event(audit.AccessRequestCreate, "access_request", "r2", audit.Success, map[string]any{"target_id": "t2", "protocol": "rdp"}))
	e.notifier.Pass(context.Background())
	if st := e.notifier.Status(id); !strings.Contains(st.LastError, "answered 500") {
		t.Fatalf("status after a failure: %+v", st)
	}
	h.status = 200
	e.notifier.retryAt[id] = e.notifier.retryAt[id].AddDate(0, 0, -1)
	e.notifier.Pass(context.Background())
	got = h.texts()
	if !strings.Contains(got[len(got)-1], "RDP access to target:t2") {
		t.Fatalf("the failed message was not sent again: %v", got)
	}
	if st := e.notifier.Status(id); st.LastError != "" || st.LastSentAt == nil {
		t.Fatalf("status after recovery: %+v", st)
	}

	// Test sends now; removal takes the channel's place in the log with it.
	if code, _, raw := e.do(t, "POST", "/api/v1/admin/notifications/"+id+"/test", nil); code != 204 {
		t.Fatalf("test: %d %s", code, raw)
	}
	if code, _, _ := e.do(t, "DELETE", "/api/v1/admin/notifications/"+id, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if at, _ := e.audit.ExportCheckpoint(context.Background(), Sink(id)); at != 0 {
		t.Fatalf("the checkpoint outlived the channel: %d", at)
	}
}

// One pass sends at most 20 messages and one line for the rest.
func TestFloodIsBounded(t *testing.T) {
	h := newHook(t)
	e := newEnv(t, toHook{h})
	_, out, _ := e.do(t, "POST", "/api/v1/admin/notifications", map[string]any{
		"name": "ops", "kind": "webhook", "events": []string{"access_requested"}, "webhook_url": "https://hooks.example.com/x",
	})
	h.key = []byte(out["signing_key"].(string))
	for i := range 25 {
		e.record(t, audit.Actor{UserID: "u"}.Event(audit.AccessRequestCreate, "access_request", fmt.Sprint(i), audit.Success, map[string]any{"target_id": "t", "protocol": "ssh"}))
	}
	e.notifier.Pass(context.Background())
	got := h.texts()
	if len(got) != 21 || !strings.HasPrefix(got[20], "5 more events this channel asked for") {
		t.Fatalf("sent %d: last %q", len(got), got[len(got)-1])
	}
}

func TestChannelInputIsChecked(t *testing.T) {
	e := newEnv(t, nil)
	for _, c := range []struct {
		body map[string]any
		want string
	}{
		{map[string]any{"name": "x", "kind": "webhook", "events": []string{"access_requested"}, "webhook_url": "http://hooks.example.com/x"}, "https://"},
		{map[string]any{"name": "x", "kind": "webhook", "events": []string{"access_requested"}, "webhook_url": "https://169.254.169.254/latest"}, "link-local"},
		{map[string]any{"name": "x", "kind": "webhook", "events": []string{"access_requested"}, "webhook_url": "https://127.0.0.1/x"}, "loopback"},
		{map[string]any{"name": "x", "kind": "webhook", "events": []string{"nope"}, "webhook_url": "https://h.example.com/x"}, "unknown kind"},
		{map[string]any{"name": "x", "kind": "email", "events": []string{}, "smtp_host": "mail.example.com", "from": "gw@example.com\r\nBcc: x@evil.com", "to": []string{"ops@example.com"}}, "from:"},
		{map[string]any{"name": "x", "kind": "email", "events": []string{}, "smtp_host": "mail.example.com", "from": "gw@example.com", "to": []string{"ops@example.com\nBcc: y@evil.com"}}, "to:"},
		{map[string]any{"name": "x", "kind": "carrier-pigeon", "events": []string{}}, "kind"},
	} {
		code, _, raw := e.do(t, "POST", "/api/v1/admin/notifications", c.body)
		if code != 400 || !strings.Contains(raw, c.want) {
			t.Errorf("%v: %d %s, want a refusal mentioning %q", c.body, code, raw, c.want)
		}
	}
	// Administrators only.
	req := httptest.NewRequest("GET", "/api/v1/admin/notifications", nil)
	req.AddCookie(e.userCk)
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("a user listed channels: %d", rr.Code)
	}
}

// fakeSMTP is enough of a mail server for one message: no TLS, which the
// sender allows only for this host's own server.
func fakeSMTP(t *testing.T) (port int, got func() string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var msg strings.Builder
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		r := bufio.NewReader(c)
		say := func(s string) { _, _ = fmt.Fprintf(c, "%s\r\n", s) }
		say("220 fake ESMTP")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					say("250 queued")
					continue
				}
				mu.Lock()
				msg.WriteString(line)
				mu.Unlock()
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250 fake")
			case strings.HasPrefix(cmd, "DATA"):
				inData = true
				say("354 go on")
			case strings.HasPrefix(cmd, "QUIT"):
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() string { mu.Lock(); defer mu.Unlock(); return msg.String() }
}

func TestEmailChannel(t *testing.T) {
	port, got := fakeSMTP(t)
	e := newEnv(t, nil)
	c := &Channel{Name: "mail", Kind: KindEmail, Enabled: true, Events: []string{EventDiskFull},
		Config: Config{SMTPHost: "127.0.0.1", SMTPPort: port, From: "gw@example.com", To: []string{"ops@example.com", "sec@example.com"}}}
	if err := e.repo.Create(context.Background(), c, Secret{}); err != nil {
		t.Fatal(err)
	}
	if err := e.notifier.Start(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	e.record(t, audit.Actor{UserID: "u"}.Event(audit.SessionConnect, "target", "t1", audit.Failure, map[string]any{"reason": "disk_full"}))
	e.notifier.Pass(context.Background())
	msg := got()
	for _, want := range []string{"From: gw@example.com\r\n", "To: ops@example.com, sec@example.com\r\n", "Subject: Zanskar: New sessions are refused: the gateway's disk is full\r\n", "running sessions go on", "https://gw.example.com/admin"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the email lacks %q:\n%s", want, msg)
		}
	}
	if st := e.notifier.Status(c.ID); st.LastError != "" || st.LastSentAt == nil {
		t.Fatalf("status: %+v", st)
	}
}

func TestMessageCannotBreakALine(t *testing.T) {
	names := func(kind, id string) string { return "evil\r\nBcc: x@evil.com" }
	m := message(audit.Event{Action: audit.AccessRequestCreate, ActorUserID: "u", Details: []byte(`{"target_id":"t","protocol":"ssh"}`)}, EventAccessRequested, names, "")
	if strings.ContainsAny(m.Subject+m.Text, "\r\n") {
		t.Fatalf("a name broke the line: %q", m.Subject)
	}
}

// A name that passed the save-time check but resolves to loopback (or to a
// metadata address, link-local) is refused when dialled (ADR 0039).
func TestWebhookDialRefusesLoopbackNames(t *testing.T) {
	h := newHook(t)
	port := h.srv.URL[strings.LastIndex(h.srv.URL, ":")+1:]
	c := &Channel{Kind: KindWebhook, secret: Secret{WebhookURL: "https://localhost:" + port + "/x", SigningKey: "k"}}
	err := (&Sender{}).Send(context.Background(), c, Message{Text: "hi"})
	if err == nil || !strings.Contains(err.Error(), "not an address notifications go to") {
		t.Fatalf("a loopback name was dialled: %v", err)
	}
	if len(h.texts()) != 0 {
		t.Fatal("the message reached a loopback listener")
	}
}
