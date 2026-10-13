// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/winrmgw/winrmtest"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/ticket"
)

// winrmRig is the connect fixture behind a real server with a stand-in WinRM
// listener; winTarget enrolls a Windows target pointing at it.
type winrmRig struct {
	*connectFixture
	url string
	wsm *winrmtest.Server
}

func newWinRMRig(t *testing.T) *winrmRig {
	t.Helper()
	f := newConnectFixture(t)
	f.h.Storage = &recording.LocalStorage{Dir: t.TempDir()}
	f.h.Registry = gateway.NewRegistry()
	f.h.DialTimeout = 5 * time.Second
	srv := httptest.NewServer(f.srv)
	t.Cleanup(srv.Close)
	return &winrmRig{connectFixture: f, url: srv.URL, wsm: winrmtest.New(t)}
}

func (r *winrmRig) winTarget(t *testing.T, name, user, pin string) string {
	t.Helper()
	c := &credential.Credential{Name: name + "-cred", Type: credential.TypePassword, Mode: credential.ModeVaulted, Username: user}
	if err := r.h.Vault.Create(r.ctx, c, &credential.Secret{Password: "pw-1"}, r.alice.ID); err != nil {
		t.Fatal(err)
	}
	host, port := r.wsm.Address(t)
	tg := &target.Target{Name: name, Address: host, OSFamily: target.Windows, Tags: map[string]string{"env": "test"},
		Ports: map[target.Protocol]int{target.WinRM: port}, Credentials: map[target.Protocol]string{target.WinRM: c.ID}}
	if err := r.h.Targets.Create(r.ctx, tg); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.h.Targets.RecordProbe(r.ctx, tg.ID, target.ProbeResult{Address: host, ResolvedIP: host,
		Capabilities: []target.Protocol{target.WinRM}, WinRMTLS: &target.TLSInfo{Fingerprint: pin, Source: "winrm"}}); err != nil {
		t.Fatal(err)
	}
	return tg.ID
}

func (r *winrmRig) open(t *testing.T, targetID string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	code, out := r.postConnect(t, r.url, targetID, "winrm")
	tok, _ := out["ticket"].(string)
	if code != http.StatusOK || tok == "" || out["ws_path"] != "/ws/winrm" {
		t.Fatalf("connect: %d %v", code, out)
	}
	return websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(r.url, "http")+"/ws/winrm?cols=100&rows=30&ticket="+tok, r.wsOptions())
}

// runConsole drives a WinRM console on ws the way a user does: a
// Get-Service line once the bridge names the session, "exit" once the target
// has run it. onReady, if set, runs when the bridge names the session. It
// returns the session id, every byte the browser received and the end reason.
func runConsole(t *testing.T, ctx context.Context, ws *websocket.Conn, onReady func(sessionID string)) (sessionID, output, endReason string) {
	t.Helper()
	send := func(d string) {
		b, _ := json.Marshal(map[string]string{"t": "i", "d": d})
		if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
			t.Fatal(err)
		}
	}
	sent := false
	for endReason == "" {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v (output %q)", err, output)
		}
		if typ == websocket.MessageText {
			var c termFrame
			_ = json.Unmarshal(data, &c)
			if c.T == "ready" {
				sessionID = c.SessionID
				if onReady != nil {
					onReady(sessionID)
				}
				send("Get-Service winrm\r")
				sent = true
			}
			if c.T == "end" {
				endReason = c.Reason
			}
			continue
		}
		output += string(data)
		if sent && strings.Contains(output, "ran: Get-Service winrm") {
			send("exit\r")
			sent = false
		}
	}
	return sessionID, output, endReason
}

// TestWinRMSessionEndToEnd: a WinRM ticket opens a recorded PowerShell
// console through the pinned listener; a typed line runs on the target and
// its output comes back; "exit" ends the session, audited.
func TestWinRMSessionEndToEnd(t *testing.T) {
	r := newWinRMRig(t)
	id := r.winTarget(t, "win-1", "admin", r.wsm.Fingerprint())
	ws, _, err := r.open(t, id) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sessionID, output, reason := runConsole(t, ctx, ws, nil)
	if reason != "user_exit" || !strings.Contains(output, "ran: Get-Service winrm") {
		t.Fatalf("end %q, output %q", reason, output)
	}
	start := lastEvent(t, r.connectFixture, "session.start")
	if start.ObjectID != sessionID {
		t.Fatalf("session.start for %s, browser saw %s", start.ObjectID, sessionID)
	}
}

// TestWinRMOutputReachesShadowTap: the registry's tap for a live WinRM
// session carries what the browser sees, so an auditor shadowing it (ADR
// 0006) gets the console rather than silence. Subscribed the way the shadow
// route does, once the bridge names the session; replay plus live stream are
// checked against the browser's bytes.
func TestWinRMOutputReachesShadowTap(t *testing.T) {
	r := newWinRMRig(t)
	id := r.winTarget(t, "win-1", "admin", r.wsm.Fingerprint())
	ws, _, err := r.open(t, id) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var (
		tap    *gateway.Tap
		live   <-chan []byte
		tapped []byte
	)
	sessionID, output, reason := runConsole(t, ctx, ws, func(id string) {
		if tap = r.h.Registry.Tap(id); tap == nil {
			t.Fatalf("live session %s has no tap", id)
		}
		var unsubscribe func()
		live, tapped, unsubscribe = tap.Subscribe()
		t.Cleanup(unsubscribe)
	})
	if reason != "user_exit" || !strings.Contains(output, "ran: Get-Service winrm") {
		t.Fatalf("session %s ended %q with output %q", sessionID, reason, output)
	}
	tapped = append(tapped, drainTap(t, ctx, live)...)
	if !strings.HasPrefix(string(tapped), output) {
		t.Fatalf("tap carried %q, browser saw %q", tapped, output)
	}
	if n := tap.Dropped.Load(); n != 0 {
		t.Fatalf("tap dropped %d chunk(s)", n)
	}
}

// TestWinRMRefusals: a listener whose certificate is not the pinned one is
// refused before the WebSocket opens, audited as a certificate mismatch, and
// never receives the credential; an account that authenticates but may not
// open a shell gets the answer that says why.
func TestWinRMRefusals(t *testing.T) {
	r := newWinRMRig(t)
	refused := func(targetID string, wantCode int) {
		t.Helper()
		ws, resp, err := r.open(t, targetID)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			ws.CloseNow()
			t.Fatal("the WebSocket opened")
		}
		if resp == nil || resp.StatusCode != wantCode {
			t.Fatalf("got %v, want %d", resp, wantCode)
		}
	}

	moved := r.winTarget(t, "win-moved", "admin", strings.Repeat("ab", 32))
	before := r.wsm.Requests.Load()
	refused(moved, http.StatusConflict)
	if ev := lastEvent(t, r.connectFixture, "target.tls.mismatch"); ev.ObjectID != moved {
		t.Fatalf("target.tls.mismatch names %s", ev.ObjectID)
	}
	if r.wsm.Requests.Load() != before {
		t.Fatal("the listener with the wrong certificate received the credential")
	}

	limited := r.winTarget(t, "win-limited", "limited", r.wsm.Fingerprint())
	refused(limited, http.StatusConflict)
}

// brokenStorage refuses every new recording, as a full disk or a lost bucket
// does.
type brokenStorage struct{ recording.LocalStorage }

func (brokenStorage) Create(context.Context, string) (io.WriteCloser, string, error) {
	return nil, "", errors.New("no space left on device")
}

// TestWinRMRecordingRefusal: a WinRM session whose recording cannot start is
// refused the way the other bridges refuse one, closing as a policy violation
// whose reason the console shows. It used to close as an internal error,
// whose reason the console drops, so the user saw a lost connection (D8).
func TestWinRMRecordingRefusal(t *testing.T) {
	r := newWinRMRig(t)
	r.h.Storage = &brokenStorage{}
	id := r.winTarget(t, "win-1", "admin", r.wsm.Fingerprint())
	ws, _, err := r.open(t, id) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for err == nil {
		_, _, err = ws.Read(ctx)
	}
	var ce websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != websocket.StatusPolicyViolation || !strings.Contains(ce.Reason, "session refused") {
		t.Fatalf("closed with %v, want a policy violation saying the session was refused", err)
	}
	var end map[string]string
	_ = json.Unmarshal(lastEvent(t, r.connectFixture, "session.end").Details, &end)
	if end["reason"] != session.EndError {
		t.Fatalf("session.end details: %v", end)
	}
}

// TestWinRMFailoverKeepsItsLink: a session opened from a failover ticket names
// the session it replaces whatever its protocol. Only SSH sessions did, so a
// desktop or WinRM failover lost its link to the session it replaced (D8).
func TestWinRMFailoverKeepsItsLink(t *testing.T) {
	r := newWinRMRig(t)
	id := r.winTarget(t, "win-1", "admin", r.wsm.Fingerprint())
	tg, err := r.h.Targets.Get(r.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	// The session that was lost, closed as the failover route closes it.
	old := &session.Session{UserID: r.alice.ID, TargetID: id, Protocol: "winrm", ClientIP: "127.0.0.1"}
	if err := r.h.Sessions.Start(r.ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := r.h.Sessions.End(r.ctx, old.ID, session.EndTargetLost); err != nil {
		t.Fatal(err)
	}
	signIn, err := r.sessions.Lookup(r.ctx, r.cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := r.h.Tickets.Issue(ticket.Grant{UserID: r.alice.ID, Username: r.alice.Username, SessionID: signIn.ID, TargetID: id,
		Protocol: "winrm", CredentialID: tg.Credentials[target.WinRM], PolicyID: r.policyIDs["test-all"], ClientIP: "127.0.0.1", FailoverFrom: old.ID})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(r.url, "http")+"/ws/winrm?cols=100&rows=30&ticket="+tok, r.wsOptions()) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	sessionID, _, reason := runConsole(t, ctx, ws, nil)
	if reason != "user_exit" {
		t.Fatalf("end %q", reason)
	}
	got, err := r.h.Sessions.Get(r.ctx, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if got.FailoverFromSessionID != old.ID {
		t.Fatalf("failover_from_session_id %q, want %q", got.FailoverFromSessionID, old.ID)
	}
}
