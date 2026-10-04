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
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/recording"
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
		Ports: map[target.Protocol]int{target.SSH: port}, Credentials: f.mustTarget(t, "ok").Credentials}
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
	srv := httptest.NewServer(f.srv)
	t.Cleanup(srv.Close)
	return &terminalRig{connectFixture: f, url: srv.URL, targetID: tg.ID}
}

func (f *connectFixture) mustTarget(t *testing.T, name string) *target.Target {
	t.Helper()
	tg, err := f.h.Targets.Get(f.ctx, f.ids[name])
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

// ticket asks for an SSH ticket over the real server, so it is bound to the
// loopback address the WebSocket will come from.
func (r *terminalRig) ticket(t *testing.T) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"target_id": r.targetID, "protocol": "ssh"})
	req, _ := http.NewRequest("POST", r.url+"/api/v1/connect", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", r.csrf)
	req.AddCookie(r.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	tok, _ := out["ticket"].(string)
	if resp.StatusCode != http.StatusOK || tok == "" {
		t.Fatalf("connect: %d %v", resp.StatusCode, out)
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

	var sessionID, output, endReason string
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
		case "end":
			endReason = c.Reason
		}
	}
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
			CredentialID: r.mustTarget(t, "ok").Credentials[target.SSH], ClientIP: "198.51.100.7"})
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

func lastEvent(t *testing.T, f *connectFixture, action string) audit.Event {
	t.Helper()
	evs, _, err := f.auditLog.List(f.ctx, audit.Filter{Action: action, Limit: 1})
	if err != nil || len(evs) == 0 {
		t.Fatalf("no %s event: %v", action, err)
	}
	return evs[0]
}
