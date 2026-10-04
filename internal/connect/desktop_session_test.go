// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/guac"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/target"
)

// stubGuacd answers the guacd handshake, reports "ready", and then reads
// until the client disconnects. It counts the connections it accepted.
func stubGuacd(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer func() { _ = c.Close() }()
				rd := guac.NewReader(c)
				if in, err := rd.Read(); err != nil || in.Opcode != "select" {
					return
				}
				_, _ = c.Write([]byte(guac.Encode("args", "VERSION_1_5_0", "hostname", "port", "password")))
				for {
					in, err := rd.Read()
					if err != nil {
						return
					}
					if in.Opcode == "connect" {
						break
					}
				}
				_, _ = c.Write([]byte(guac.Encode("ready", "$conn-1")))
				for {
					if in, err := rd.Read(); err != nil || in.Opcode == "disconnect" {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), &accepted
}

// fakeRDP answers the RDP negotiation by selecting TLS and then presents a
// throwaway certificate. It returns its port and that certificate's SHA-256.
func fakeRDP(t *testing.T) (int, string) {
	t.Helper()
	donor := httptest.NewTLSServer(http.NotFoundHandler())
	cert := donor.TLS.Certificates[0]
	donor.Close()
	sum := sha256.Sum256(cert.Certificate[0])
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	confirm := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				if _, err := io.ReadFull(c, make([]byte, 19)); err != nil {
					return
				}
				_, _ = c.Write(confirm)
				_ = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}).Handshake()
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, hex.EncodeToString(sum[:])
}

// desktopRig is the connect fixture behind a real server, with desktop
// sessions wired to stubGuacd and a policy letting alice use RDP and VNC on
// targets tagged desk=yes.
type desktopRig struct {
	*connectFixture
	url      string
	accepted *atomic.Int32
}

func newDesktopRig(t *testing.T) *desktopRig {
	t.Helper()
	f := newConnectFixture(t)
	addr, accepted := stubGuacd(t)
	f.h.GuacdAddr = func() string { return addr }
	f.h.Storage = &recording.LocalStorage{Dir: t.TempDir()}
	f.h.Registry = gateway.NewRegistry()
	f.h.Prober = &target.Prober{AllowLoopback: true}
	f.h.DialTimeout = 3 * time.Second
	if err := f.h.Policies.Create(f.ctx, &policy.Policy{Name: "desk", UserID: f.alice.ID, Enabled: true, IdleTimeoutMinutes: 15,
		Selector: policy.Selector{Tags: map[string]string{"desk": "yes"}}, Protocols: []string{"rdp", "vnc"}}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(f.srv)
	t.Cleanup(srv.Close)
	return &desktopRig{connectFixture: f, url: srv.URL, accepted: accepted}
}

func (r *desktopRig) addTarget(t *testing.T, name string, ports map[target.Protocol]int, pin string) string {
	t.Helper()
	cred := r.mustTarget(t, "ok").Credentials[target.SSH]
	tg := &target.Target{Name: name, Address: "127.0.0.1", OSFamily: target.Windows, Tags: map[string]string{"desk": "yes"},
		Ports: ports, Credentials: map[target.Protocol]string{target.RDP: cred, target.VNC: cred}}
	if err := r.h.Targets.Create(r.ctx, tg); err != nil {
		t.Fatal(err)
	}
	if pin != "" {
		if _, _, err := r.h.Targets.RecordProbe(r.ctx, tg.ID, target.ProbeResult{Address: tg.Address, ResolvedIP: tg.Address,
			Capabilities: []target.Protocol{target.RDP}, TLS: &target.TLSInfo{Fingerprint: pin, Source: "rdp"}}); err != nil {
			t.Fatal(err)
		}
	}
	return tg.ID
}

func (r *desktopRig) ticket(t *testing.T, targetID, proto string) string {
	t.Helper()
	code, out := r.postConnect(t, r.url, targetID, proto)
	tok, _ := out["ticket"].(string)
	if code != http.StatusOK || tok == "" || out["ws_path"] != "/ws/desktop" {
		t.Fatalf("connect %s: %d %v", proto, code, out)
	}
	return tok
}

func (r *desktopRig) dial(ctx context.Context, tok string) (*websocket.Conn, *http.Response, error) {
	return websocket.Dial(ctx, "ws"+strings.TrimPrefix(r.url, "http")+"/ws/desktop?width=1024&height=768&ticket="+tok,
		&websocket.DialOptions{Subprotocols: []string{"guacamole"}})
}

// TestDesktopSessionEndToEnd: a VNC ticket opens a recorded session through
// guacd: the browser learns the session id and the policy's flags, guacd's
// instructions reach it, and disconnecting ends the session with its
// recording finished and the start audited.
func TestDesktopSessionEndToEnd(t *testing.T) {
	r := newDesktopRig(t)
	id := r.addTarget(t, "vnc-box", map[target.Protocol]int{target.VNC: 5900}, "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ws, _, err := r.dial(ctx, r.ticket(t, id, "vnc")) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	// The gateway consumes guacd's "ready" in the handshake; the browser
	// first gets the session id and the policy flags.
	var seen string
	for !strings.Contains(seen, "7.zanskar,") {
		_, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v (got %q)", err, seen)
		}
		seen += string(data)
	}
	if !strings.Contains(seen, "7.zanskar,4.file,1.0,9.clipboard,1.0;") {
		t.Fatalf("policy flags missing from %q", seen)
	}
	start := lastEvent(t, r.connectFixture, "session.start")
	var d map[string]any
	_ = json.Unmarshal(start.Details, &d)
	if d["protocol"] != "vnc" || d["target_id"] != id || !strings.Contains(seen, start.ObjectID) {
		t.Fatalf("session.start %v for %s; browser saw %q", d, start.ObjectID, seen)
	}

	if err := ws.Write(ctx, websocket.MessageText, []byte(guac.Encode("disconnect"))); err != nil {
		t.Fatal(err)
	}
	ended := false
	for i := 0; i < 200 && !ended; i++ {
		s, err := r.h.Sessions.Get(r.ctx, start.ObjectID)
		ended = err == nil && s.EndedAt != nil
		if !ended {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !ended {
		t.Fatal("the desktop session never ended")
	}
	rec, err := r.h.Sessions.GetRecording(r.ctx, d["recording_id"].(string))
	if err != nil || rec.FinishedAt == nil || rec.Format != "guac" {
		t.Fatalf("recording %+v %v", rec, err)
	}
}

// TestDesktopRefusesMismatchedRDPCertificate: the gateway checks the target's
// RDP certificate against the pin itself, before guacd (which connects
// without checking) ever hears of the session. A match goes through.
func TestDesktopRefusesMismatchedRDPCertificate(t *testing.T) {
	r := newDesktopRig(t)
	port, fp := fakeRDP(t)
	wrong := r.addTarget(t, "rdp-moved", map[target.Protocol]int{target.RDP: port}, strings.Repeat("ab", 32))
	right := r.addTarget(t, "rdp-pinned", map[target.Protocol]int{target.RDP: port}, fp)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ws, resp, err := r.dial(ctx, r.ticket(t, wrong, "rdp"))
	if err == nil {
		ws.CloseNow()
		t.Fatal("a mismatched certificate opened a desktop session")
	}
	if resp == nil || resp.StatusCode != http.StatusConflict {
		t.Fatalf("got %v, want 409 certificate_mismatch", resp)
	}
	_ = resp.Body.Close()
	if n := r.accepted.Load(); n != 0 {
		t.Fatalf("guacd was contacted %d time(s) for a refused session", n)
	}

	ws, _, err = r.dial(ctx, r.ticket(t, right, "rdp")) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatalf("the pinned certificate must be accepted: %v", err)
	}
	// The first message names the session; close it and wait for the
	// gateway to finish it, so its recording is not still being written
	// when the test's temporary directory is removed.
	_, first, err := ws.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ws.CloseNow()
	r.waitEnded(t, sessionIDFrom(string(first)))
}

// sessionIDFrom reads the session id from the first desktop message,
// guac.Encode("", id): "0.,<len>.<id>;".
func sessionIDFrom(msg string) string {
	if i := strings.Index(msg, ","); i >= 0 {
		rest := msg[i+1:]
		if j := strings.Index(rest, "."); j >= 0 {
			return strings.TrimSuffix(strings.SplitN(rest[j+1:], ";", 2)[0], ";")
		}
	}
	return ""
}

// waitEnded blocks until the session's row says it ended.
func (r *desktopRig) waitEnded(t *testing.T, id string) {
	t.Helper()
	for i := 0; i < 250; i++ {
		if s, err := r.h.Sessions.Get(r.ctx, id); err == nil && s.EndedAt != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("session %q never ended", id)
}

// TestDesktopRouteRefusals: a desktop endpoint will not redeem an SSH
// ticket, and refuses outright while desktop sessions are switched off.
func TestDesktopRouteRefusals(t *testing.T) {
	r := newDesktopRig(t)
	sshTicket := func() string {
		_, out := r.postConnect(t, r.url, r.ids["ok"], "ssh")
		return out["ticket"].(string)
	}
	refused := func(what, tok string, want int) {
		t.Helper()
		ws, resp, err := r.dial(context.Background(), tok)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			ws.CloseNow()
		}
		if err == nil || resp == nil || resp.StatusCode != want {
			t.Fatalf("%s: %v %v, want %d", what, err, resp, want)
		}
	}
	refused("an SSH ticket on the desktop route", sshTicket(), http.StatusBadRequest)
	id := r.addTarget(t, "vnc-off", map[target.Protocol]int{target.VNC: 5900}, "")
	tok := r.ticket(t, id, "vnc")
	r.h.GuacdAddr = func() string { return "" }
	refused("desktop sessions switched off", tok, http.StatusNotImplemented)
}
