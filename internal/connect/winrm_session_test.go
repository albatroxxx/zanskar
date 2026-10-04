// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"encoding/json"
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
	"github.com/albatroxxx/zanskar/internal/target"
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
	return websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(r.url, "http")+"/ws/winrm?cols=100&rows=30&ticket="+tok, nil)
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
	send := func(d string) {
		b, _ := json.Marshal(map[string]string{"t": "i", "d": d})
		if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
			t.Fatal(err)
		}
	}

	var output, sessionID, reason string
	sent := false
	for reason == "" {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v (output %q)", err, output)
		}
		if typ == websocket.MessageText {
			var c struct {
				T         string `json:"t"`
				SessionID string `json:"session_id"`
				Reason    string `json:"reason"`
			}
			_ = json.Unmarshal(data, &c)
			if c.T == "ready" {
				sessionID = c.SessionID
				send("Get-Service winrm\r")
				sent = true
			}
			if c.T == "end" {
				reason = c.Reason
			}
			continue
		}
		output += string(data)
		if sent && strings.Contains(output, "ran: Get-Service winrm") {
			send("exit\r")
			sent = false
		}
	}
	if reason != "user_exit" || !strings.Contains(output, "ran: Get-Service winrm") {
		t.Fatalf("end %q, output %q", reason, output)
	}
	start := lastEvent(t, r.connectFixture, "session.start")
	if start.ObjectID != sessionID {
		t.Fatalf("session.start for %s, browser saw %s", start.ObjectID, sessionID)
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
