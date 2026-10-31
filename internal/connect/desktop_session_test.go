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

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/guac"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/policy/policytest"
	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/target"
)

// stubGuacd answers the guacd handshake, reports "ready", and then reads
// until the client disconnects, playing the instructions an "emit" carries
// as its own output. It counts the connections it accepted.
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
					in, err := rd.Read()
					if err != nil || in.Opcode == "disconnect" {
						return
					}
					if in.Opcode == "emit" {
						for _, raw := range in.Args {
							_, _ = c.Write([]byte(raw))
						}
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
	desk := policytest.Policy("desk", []policy.Subject{policytest.User(f.alice.ID)}, policytest.Tagged(protocol.KindHost, map[string]string{"desk": "yes"}, "rdp", "vnc"))
	if err := f.h.Policies.Create(f.ctx, desk); err != nil {
		t.Fatal(err)
	}
	f.policyIDs[desk.Name] = desk.ID
	srv := httptest.NewServer(f.srv)
	t.Cleanup(srv.Close)
	return &desktopRig{connectFixture: f, url: srv.URL, accepted: accepted}
}

func (r *desktopRig) addTarget(t *testing.T, name string, ports map[target.Protocol]int, pin string) string {
	t.Helper()
	tg := &target.Target{Name: name, Address: "127.0.0.1", OSFamily: target.Windows, Tags: map[string]string{"desk": "yes"},
		Ports: ports, Credentials: map[target.Protocol]string{target.RDP: r.vaulted, target.VNC: r.vaulted}}
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
		r.wsOptions("guacamole"))
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

// TestDesktopEndedByGuacdKeepsItsWords: a desktop that guacd ends with an
// "error" instruction (the RDP server disconnecting with a reason guacd has
// no words for) still ends target_lost, which failover depends on, and its
// session.end event carries guacd's words and status, so an administrator
// reading Events sees more than "target lost".
func TestDesktopEndedByGuacdKeepsItsWords(t *testing.T) {
	r := newDesktopRig(t)
	id := r.addTarget(t, "win-box", map[target.Protocol]int{target.VNC: 5900}, "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ws, _, err := r.dial(ctx, r.ticket(t, id, "vnc")) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	if _, _, err := ws.Read(ctx); err != nil {
		t.Fatal(err)
	}
	sessionID := lastEvent(t, r.connectFixture, "session.start").ObjectID
	if err := ws.Write(ctx, websocket.MessageText, []byte(guac.Encode("emit", guac.Encode("error", "Upstream error.", "515")))); err != nil {
		t.Fatal(err)
	}
	if row, audited := r.endedWith(t, sessionID); row != session.EndTargetLost || audited != session.EndTargetLost {
		t.Fatalf("ended %q (session.end says %q), want target_lost", row, audited)
	}
	evs, _, err := r.auditLog.List(r.ctx, audit.Filter{Action: "session.end", ObjectID: sessionID})
	if err != nil || len(evs) != 1 {
		t.Fatalf("session.end: %v %v", evs, err)
	}
	var d map[string]string
	_ = json.Unmarshal(evs[0].Details, &d)
	if d["detail"] != "Upstream error." || d["status"] != "0x0203" || d["target_id"] != id {
		t.Fatalf("session.end details %v", d)
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
	// The refusal is on the record, as WinRM's and SSH's are (ADR 0012).
	evs, _, err := r.h.Audit.List(ctx, audit.Filter{Action: "target.tls.mismatch", Limit: 1})
	if err != nil || len(evs) != 1 || evs[0].Outcome != audit.Failure || !strings.Contains(string(evs[0].Details), `"protocol":"rdp"`) || !strings.Contains(string(evs[0].Details), fp) {
		t.Fatalf("mismatch audit: %v %v", evs, err)
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
	if _, after, ok := strings.Cut(msg, ","); ok {
		rest := after
		if _, after, ok := strings.Cut(rest, "."); ok {
			return strings.TrimSuffix(strings.SplitN(after, ";", 2)[0], ";")
		}
	}
	return ""
}

// waitEnded blocks until the session's row says it ended.
func (f *connectFixture) waitEnded(t *testing.T, id string) {
	t.Helper()
	for range 250 {
		if s, err := f.h.Sessions.Get(f.ctx, id); err == nil && s.EndedAt != nil {
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

// TestDesktopRefusalIsNotALostTarget: a desktop the gateway refuses before
// its bridge starts, here because guacd is not running, is told so with
// status 523 (session closed) and the reason. It was 519, the lost-target
// status, so the console said the connection to the target was lost and, on
// an autoscaling group, offered another instance, which cannot help.
func TestDesktopRefusalIsNotALostTarget(t *testing.T) {
	r := newDesktopRig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	down := ln.Addr().String()
	_ = ln.Close()
	r.h.GuacdAddr = func() string { return down }
	id := r.addTarget(t, "vnc-box", map[target.Protocol]int{target.VNC: 5900}, "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ws, _, err := r.dial(ctx, r.ticket(t, id, "vnc")) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	_, data, err := ws.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	in, err := guac.Parse(string(data))
	if err != nil || in.Opcode != "error" || len(in.Args) != 2 {
		t.Fatalf("got %q (%v), want an error instruction", data, err)
	}
	if in.Args[1] != "523" || !strings.Contains(in.Args[0], "guacd") {
		t.Fatalf("refusal %q with status %s, want guacd's absence with 523", in.Args[0], in.Args[1])
	}
}
