// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/ticket"
)

// shellTarget is an SSH server that accepts the fixture's vaulted credential
// (svc / pw-123456) and runs upperShell. It returns its port and host key
// fingerprint.
func shellTarget(t *testing.T) (int, string) {
	t.Helper()
	port, fp, _ := fakeSSHTarget(t, "svc", "pw-123456", func(ch ssh.Channel, reqs <-chan *ssh.Request) {
		for r := range reqs {
			if r.WantReply {
				_ = r.Reply(r.Type == "pty-req" || r.Type == "shell" || r.Type == "window-change", nil)
			}
			if r.Type == "shell" {
				go upperShell(ch)
			}
		}
	})
	return port, fp
}

func upperShell(ch ssh.Channel) {
	defer func() { _ = ch.Close() }()
	_, _ = ch.Write([]byte("$ "))
	buf := make([]byte, 256)
	var line []byte
	for {
		n, err := ch.Read(buf)
		if err != nil {
			return
		}
		line = append(line, buf[:n]...)
		for {
			i := bytes.IndexByte(line, '\r')
			if i < 0 {
				break
			}
			cmd := strings.TrimSpace(string(line[:i]))
			line = line[i+1:]
			if cmd == "exit" {
				_, _ = ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, 0))
				return
			}
			_, _ = ch.Write([]byte("\r\n" + strings.ToUpper(cmd) + "\r\n$ "))
		}
	}
}

// terminalRig puts the fixture behind a real HTTP server (WebSockets need
// one) and enrolls an SSH target pointing at shellTarget, trusting
// trustedFP as its host key.
type terminalRig struct {
	*connectFixture
	url      string
	targetID string
}

func newTerminalRig(t *testing.T, port int, trustedFP string) *terminalRig {
	t.Helper()
	f := newConnectFixture(t)
	f.h.Storage = &recording.LocalStorage{Dir: t.TempDir()}
	f.h.Registry = gateway.NewRegistry()
	f.h.DialTimeout = 5 * time.Second
	tg := &target.Target{Name: "shell", Address: "127.0.0.1", OSFamily: target.Linux, Tags: map[string]string{"env": "test"},
		Ports: map[target.Protocol]int{target.SSH: port}, Credentials: map[target.Protocol]string{target.SSH: f.vaulted}}
	if err := f.h.Targets.Create(f.ctx, tg); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.h.Targets.RecordProbe(f.ctx, tg.ID, target.ProbeResult{Address: tg.Address, ResolvedIP: tg.Address,
		Capabilities: []target.Protocol{target.SSH}, SSHHostKey: &target.SSHHostKey{Fingerprint: trustedFP, Type: "ssh-ed25519"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.Targets.TrustHostKey(f.ctx, tg.ID, trustedFP); err != nil {
		t.Fatal(err)
	}
	// Every request the rig serves is counted, a WebSocket one for the whole
	// session it runs, and the cleanup waits for them: a session still
	// closing its recording when the temporary directory goes made the
	// directory's removal fail now and then. Cleanups run last first, so the
	// server closes, then this waits, then the directory goes.
	var inflight sync.WaitGroup
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inflight.Add(1)
		defer inflight.Done()
		f.srv.ServeHTTP(w, r)
	}))
	t.Cleanup(func() {
		done := make(chan struct{})
		go func() { inflight.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("a session was still running 10s after the test ended")
		}
	})
	t.Cleanup(srv.Close)
	return &terminalRig{connectFixture: f, url: srv.URL, targetID: tg.ID}
}

// ticket asks for an SSH ticket over the real server, so it is bound to the
// loopback address the WebSocket will come from.
func (r *terminalRig) ticket(t *testing.T) string {
	t.Helper()
	code, out := r.postConnect(t, r.url, r.targetID, "ssh")
	tok, _ := out["ticket"].(string)
	if code != http.StatusOK || tok == "" {
		t.Fatalf("connect: %d %v", code, out)
	}
	return tok
}

func (r *terminalRig) dial(ctx context.Context, tok string) (*websocket.Conn, *http.Response, error) {
	return websocket.Dial(ctx, "ws"+strings.TrimPrefix(r.url, "http")+"/ws/terminal?cols=80&rows=24&ticket="+tok, nil)
}

type termFrame struct {
	T         string `json:"t"`
	SessionID string `json:"session_id"`
	Reason    string `json:"reason"`
}

// runShell drives a terminal session on ws the way a user does: "hello" at
// the first prompt, "exit" once the shell has echoed HELLO. onReady, if set,
// runs when the bridge names the session. It returns the session id, every
// byte the browser received and the end reason.
func runShell(t *testing.T, ctx context.Context, ws *websocket.Conn, onReady func(sessionID string)) (sessionID, output, endReason string) {
	t.Helper()
	send := func(d string) {
		b, _ := json.Marshal(map[string]string{"t": "i", "d": d})
		if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
			t.Fatal(err)
		}
	}
	for endReason == "" {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v (output so far %q)", err, output)
		}
		if typ == websocket.MessageBinary {
			output += string(data)
			switch {
			case strings.Count(output, "$ ") == 1 && !strings.Contains(output, "HELLO"):
				send("hello\r")
			case strings.Contains(output, "HELLO") && strings.Count(output, "$ ") == 2:
				send("exit\r")
			}
			continue
		}
		var c termFrame
		_ = json.Unmarshal(data, &c)
		switch c.T {
		case "ready":
			sessionID = c.SessionID
			if onReady != nil {
				onReady(sessionID)
			}
		case "end":
			endReason = c.Reason
		}
	}
	return sessionID, output, endReason
}

// drainTap collects a tap subscription until the tap closes, which the
// registry does when the session's bridge returns.
func drainTap(t *testing.T, ctx context.Context, ch <-chan []byte) []byte {
	t.Helper()
	var out []byte
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("tap never closed: %v (collected %q)", ctx.Err(), out)
		case chunk, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, chunk...)
		}
	}
}

// TestTerminalSessionEndToEnd: a ticket opens one recorded SSH session, the
// shell's output reaches the browser, and the session's start and end are in
// the audit log with the recording finished and hashed.
func TestTerminalSessionEndToEnd(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ws, _, err := r.dial(ctx, r.ticket(t)) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()

	sessionID, output, endReason := runShell(t, ctx, ws, nil)
	if sessionID == "" || !strings.Contains(output, "HELLO") || endReason != "user_exit" {
		t.Fatalf("session %q output %q end %q", sessionID, output, endReason)
	}

	// The bridge finishes the session after the end frame; wait for it.
	var ended bool
	for i := 0; i < 100 && !ended; i++ {
		s, err := r.h.Sessions.Get(r.ctx, sessionID)
		ended = err == nil && s.EndedAt != nil && s.EndReason == "user_exit"
		if !ended {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !ended {
		t.Fatal("session not ended with user_exit")
	}

	start := lastEvent(t, r.connectFixture, "session.start")
	var d map[string]any
	_ = json.Unmarshal(start.Details, &d)
	if start.ObjectID != sessionID || start.ActorUserID != r.alice.ID || d["target_id"] != r.targetID {
		t.Fatalf("session.start %+v %v", start, d)
	}
	if end := lastEvent(t, r.connectFixture, "session.end"); end.ObjectID != sessionID {
		t.Fatalf("session.end for %s, want %s", end.ObjectID, sessionID)
	}
	recID, _ := d["recording_id"].(string)
	rec, err := r.h.Sessions.GetRecording(r.ctx, recID)
	if err != nil || rec.FinishedAt == nil || rec.SizeBytes == 0 || len(rec.SHA256) != 64 {
		t.Fatalf("recording %+v %v", rec, err)
	}
	raw, err := os.ReadFile(strings.TrimPrefix(rec.StorageURI, "file://"))
	if err != nil || !strings.Contains(string(raw), "HELLO") {
		t.Fatalf("recording does not hold the session output: %v", err)
	}
}

// TestTerminalOutputReachesShadowTap: the registry's tap for a live SSH
// session carries what the browser sees, so an auditor shadowing it (ADR
// 0006) gets the screen rather than silence. The test subscribes the way the
// shadow route does, once the bridge names the session, and checks the
// replay plus the live stream against the browser's bytes.
func TestTerminalOutputReachesShadowTap(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ws, _, err := r.dial(ctx, r.ticket(t)) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()

	var (
		tap    *gateway.Tap
		live   <-chan []byte
		tapped []byte
	)
	sessionID, output, endReason := runShell(t, ctx, ws, func(id string) {
		if tap = r.h.Registry.Tap(id); tap == nil {
			t.Fatalf("live session %s has no tap", id)
		}
		var unsubscribe func()
		live, tapped, unsubscribe = tap.Subscribe()
		t.Cleanup(unsubscribe)
	})
	if endReason != "user_exit" || !strings.Contains(output, "HELLO") {
		t.Fatalf("session %s ended %q with output %q", sessionID, endReason, output)
	}
	tapped = append(tapped, drainTap(t, ctx, live)...)
	// The bridge hands each chunk to the tap before the browser, so the tap
	// holds at least what the browser read before the end frame.
	if !strings.HasPrefix(string(tapped), output) {
		t.Fatalf("tap carried %q, browser saw %q", tapped, output)
	}
	if n := tap.Dropped.Load(); n != 0 {
		t.Fatalf("tap dropped %d chunk(s)", n)
	}
}

// TestTerminalTickets: a ticket is single-use, bound to the address that
// asked for it, and a made-up one opens nothing. Each is refused before the
// WebSocket upgrade, so no session row is written.
func TestTerminalTickets(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	refused := func(t *testing.T, tok string) {
		t.Helper()
		ws, resp, err := r.dial(ctx, tok)
		if err == nil {
			ws.CloseNow()
			t.Fatal("WebSocket opened")
		}
		if resp == nil || resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("got %v, want 401", resp)
		}
		_ = resp.Body.Close()
	}

	t.Run("made up", func(t *testing.T) { refused(t, "not-a-ticket") })

	t.Run("used twice", func(t *testing.T) {
		tok := r.ticket(t)
		ws, _, err := r.dial(ctx, tok) //nolint:bodyclose // the library closes the handshake body
		if err != nil {
			t.Fatal(err)
		}
		ws.CloseNow()
		refused(t, tok)
	})

	t.Run("from another address", func(t *testing.T) {
		tok, err := r.h.Tickets.Issue(ticket.Grant{UserID: r.alice.ID, Username: "alice", TargetID: r.targetID, Protocol: "ssh",
			CredentialID: r.vaulted, ClientIP: "198.51.100.7"})
		if err != nil {
			t.Fatal(err)
		}
		refused(t, tok)
	})
}

// TestTerminalRefusesChangedHostKey: when the target presents a host key
// other than the trusted one, the session ends before any credential is
// sent, the user is told why, and the mismatch is audited.
func TestTerminalRefusesChangedHostKey(t *testing.T) {
	port, _ := shellTarget(t)
	r := newTerminalRig(t, port, "SHA256:"+strings.Repeat("B", 43))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ws, _, err := r.dial(ctx, r.ticket(t)) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	_, _, err = ws.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusPolicyViolation || !strings.Contains(err.Error(), "host key mismatch") {
		t.Fatalf("got %v, want a policy-violation close naming the host key mismatch", err)
	}
	if ev := lastEvent(t, r.connectFixture, "target.hostkey.mismatch"); ev.ObjectID != r.targetID || ev.Outcome != audit.Failure {
		t.Fatalf("mismatch audit %+v", ev)
	}
	end := lastEvent(t, r.connectFixture, "session.end")
	var d map[string]string
	_ = json.Unmarshal(end.Details, &d)
	if d["reason"] != "error" {
		t.Fatalf("session.end reason %q, want error", d["reason"])
	}
}

// TestTerminalRefusesTicketForAnotherProtocol: a ticket is good for the
// route of the protocol it was issued for and no other. The target is a
// Windows box that also runs OpenSSH with a trusted host key, reached through
// a policy that grants alice RDP only, and its RDP credential is one sshd
// accepts; the SSH route must still refuse the RDP ticket before the upgrade,
// so no session row and no session.start exist. The database route refuses
// it the same way, and an SSH ticket on an SSH policy still works.
func TestTerminalRefusesTicketForAnotherProtocol(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// The fixture's vaulted credential, svc / pw-123456, is what shellTarget
	// accepts; here it is the target's RDP credential.
	tg := &target.Target{Name: "win-with-sshd", Address: "127.0.0.1", OSFamily: target.Windows, Tags: map[string]string{"role": "rdp-only"},
		Ports: map[target.Protocol]int{target.SSH: port}, Credentials: map[target.Protocol]string{target.RDP: r.vaulted}}
	if err := r.h.Targets.Create(r.ctx, tg); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.h.Targets.RecordProbe(r.ctx, tg.ID, target.ProbeResult{Address: tg.Address, ResolvedIP: tg.Address,
		Capabilities: []target.Protocol{target.SSH, target.RDP}, SSHHostKey: &target.SSHHostKey{Fingerprint: fp, Type: "ssh-ed25519"},
		TLS: &target.TLSInfo{Fingerprint: strings.Repeat("ab", 32), Source: "rdp"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.h.Targets.TrustHostKey(r.ctx, tg.ID, fp); err != nil {
		t.Fatal(err)
	}
	if err := r.h.Policies.Create(r.ctx, &policy.Policy{Name: "rdp-only", UserID: r.alice.ID, Enabled: true, IdleTimeoutMinutes: 15,
		Selector: policy.Selector{Tags: map[string]string{"role": "rdp-only"}}, Protocols: []string{"rdp"}}); err != nil {
		t.Fatal(err)
	}
	if code, out := r.postConnect(t, r.url, tg.ID, "ssh"); code != http.StatusForbidden || out["code"] != "policy_denied" {
		t.Fatalf("ssh on the rdp-only target: %d %v, want 403 policy_denied", code, out)
	}
	rdpTicket := func() string {
		t.Helper()
		code, out := r.postConnect(t, r.url, tg.ID, "rdp")
		tok, _ := out["ticket"].(string)
		if code != http.StatusOK || tok == "" || out["ws_path"] != "/ws/desktop" {
			t.Fatalf("connect rdp: %d %v", code, out)
		}
		return tok
	}
	refused := func(route, tok string) {
		t.Helper()
		ws, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(r.url, "http")+route+"?cols=80&rows=24&ticket="+tok, nil)
		if err == nil {
			ws.CloseNow()
			t.Fatalf("%s opened a session on an RDP ticket", route)
		}
		if resp == nil {
			t.Fatalf("%s: %v", route, err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if resp.StatusCode != http.StatusBadRequest || out["code"] != "bad_request" {
			t.Fatalf("%s: got %d %v, want 400 bad_request", route, resp.StatusCode, out)
		}
	}
	// Tickets are single-use, so each route gets its own.
	refused("/ws/terminal", rdpTicket())
	refused("/ws/database", rdpTicket())
	if rows, _, err := r.h.Sessions.List(r.ctx, session.Filter{TargetID: tg.ID}); err != nil || len(rows) != 0 {
		t.Fatalf("sessions on the rdp-only target: %d %v, want none", len(rows), err)
	}
	// Nothing has opened a session yet, so the log must hold no session.start.
	if evs, _, err := r.auditLog.List(r.ctx, audit.Filter{Action: "session.start"}); err != nil || len(evs) != 0 {
		t.Fatalf("session.start events: %d %v, want none", len(evs), err)
	}

	// An SSH ticket issued under an SSH policy opens the terminal as before.
	ws, _, err := r.dial(ctx, r.ticket(t)) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	_, first, err := ws.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var c termFrame
	_ = json.Unmarshal(first, &c)
	if c.T != "ready" || c.SessionID == "" {
		t.Fatalf("first frame %s, want ready", first)
	}
	ws.CloseNow()
	r.waitEnded(t, c.SessionID)
}

func lastEvent(t *testing.T, f *connectFixture, action string) audit.Event {
	t.Helper()
	evs, _, err := f.auditLog.List(f.ctx, audit.Filter{Action: action, Limit: 1})
	if err != nil || len(evs) == 0 {
		t.Fatalf("no %s event: %v", action, err)
	}
	return evs[0]
}
