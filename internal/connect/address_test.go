// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/target"
)

// The tests in this file run sessions under the address rules production
// uses, with no loopback allowance (L1). A target named "localhost" stands
// for any name that resolves somewhere the gateway must never connect to: an
// address can pass every check when it is saved and probed and still point
// there by the time a session dials it. Every protocol must resolve the name,
// check the answer and refuse, and the refusal is audited.

// fakeResolver answers lookups from a table; a name it does not hold does not
// exist. Names under .invalid never resolve for real (RFC 2606), so a session
// that reaches its target through one got there by this answer.
type fakeResolver map[string][]string

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	answers, ok := f[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]net.IPAddr, 0, len(answers))
	for _, a := range answers {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out, nil
}

// setAddress moves a target without Repo.Update, which would clear the
// trusted host key and pins these tests need kept.
func (f *connectFixture) setAddress(t *testing.T, id, address string) {
	t.Helper()
	if _, err := f.db.ExecContext(f.ctx, f.db.Rebind(`UPDATE targets SET address = ? WHERE id = ?`), address, id); err != nil {
		t.Fatal(err)
	}
}

// wantAddressRefused checks the refusal was audited as a failed connect.
func wantAddressRefused(t *testing.T, f *connectFixture, targetID, proto string) {
	t.Helper()
	ev := lastEvent(t, f, "session.connect")
	var d map[string]any
	_ = json.Unmarshal(ev.Details, &d)
	if ev.Outcome != audit.Failure || ev.ObjectID != targetID || d["reason"] != "address_forbidden" || d["protocol"] != proto {
		t.Fatalf("refusal audited as %+v %v", ev, d)
	}
}

// TestTerminalRefusesForbiddenName: the SSH session is refused where it
// would dial, and the browser is told why in the close frame the console
// shows.
func TestTerminalRefusesForbiddenName(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	r.h.Prober = &target.Prober{}
	r.setAddress(t, r.targetID, "localhost")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ws, _, err := r.dial(ctx, r.ticket(t)) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			var ce websocket.CloseError
			if !errors.As(err, &ce) || ce.Code != websocket.StatusPolicyViolation || !strings.Contains(ce.Reason, "address") {
				t.Fatalf("closed with %v, want a policy-violation close about the address", err)
			}
			break
		}
		if typ == websocket.MessageText && strings.Contains(string(data), `"ready"`) {
			t.Fatalf("a session started on a name that resolves to loopback: %s", data)
		}
	}
	wantAddressRefused(t, r.connectFixture, r.targetID, "ssh")
}

// TestWinRMRefusesForbiddenName: refused before the upgrade, where WinRM
// dials, and nothing reaches the listener.
func TestWinRMRefusesForbiddenName(t *testing.T) {
	r := newWinRMRig(t)
	id := r.winTarget(t, "win-named", "admin", r.wsm.Fingerprint())
	r.h.Prober = &target.Prober{}
	r.setAddress(t, id, "localhost")
	before := r.wsm.Requests.Load()

	ws, resp, err := r.open(t, id)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		ws.CloseNow()
		t.Fatal("a session started on a name that resolves to loopback")
	}
	if resp == nil || resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("refused with %v %v, want 422", resp, err)
	}
	if n := r.wsm.Requests.Load() - before; n != 0 {
		t.Fatalf("%d request(s) reached the WinRM listener", n)
	}
	wantAddressRefused(t, r.connectFixture, id, "winrm")
}

// TestDesktopRefusesForbiddenName: refused before the upgrade for RDP and
// VNC alike, and guacd is never asked to connect. RDP used to answer
// certificate_mismatch here, its pin check having failed on the address.
func TestDesktopRefusesForbiddenName(t *testing.T) {
	r := newDesktopRig(t)
	rdpPort, pin := fakeRDP(t)
	ids := map[string]string{
		"vnc": r.addTarget(t, "vnc-named", map[target.Protocol]int{target.VNC: 5900}, ""),
		"rdp": r.addTarget(t, "rdp-named", map[target.Protocol]int{target.RDP: rdpPort}, pin),
	}
	r.h.Prober = &target.Prober{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for proto, id := range ids {
		r.setAddress(t, id, "localhost")
		ws, resp, err := r.dial(ctx, r.ticket(t, id, proto))
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			ws.CloseNow()
			t.Fatalf("%s: a session started on a name that resolves to loopback", proto)
		}
		if resp == nil || resp.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("%s: refused with %v %v, want 422", proto, resp, err)
		}
		wantAddressRefused(t, r.connectFixture, id, proto)
	}
	if n := r.accepted.Load(); n != 0 {
		t.Fatalf("guacd was asked for %d connection(s)", n)
	}
}

// redeemDatabase enrols a database target at address and redeems a ticket
// for it with a plain GET. The address check comes before the upgrade, which
// a plain GET cannot complete (426); the docker path does not exist, so no
// container could start either way.
func redeemDatabase(t *testing.T, f *connectFixture, name, address string) (string, int, map[string]any) {
	t.Helper()
	f.h.Registry = gateway.NewRegistry()
	f.h.DockerPath = "/nonexistent/docker"
	cred := &credential.Credential{Name: name + "-cred", Type: credential.TypePassword, Mode: credential.ModeVaulted, Username: "postgres"}
	if err := f.h.Vault.Create(f.ctx, cred, &credential.Secret{Password: "pw-for-the-sidecar"}, f.alice.ID); err != nil {
		t.Fatal(err)
	}
	tg := &target.Target{Name: name, Address: address, OSFamily: target.Linux, Engine: "postgres", TLSMode: "disable",
		Tags: map[string]string{"env": "test"}, Credentials: map[target.Protocol]string{target.Database: cred.ID}}
	if err := f.h.Targets.Create(f.ctx, tg); err != nil {
		t.Fatal(err)
	}
	code, out := f.connect(t, map[string]any{"target_id": tg.ID, "protocol": "database"})
	tok, _ := out["ticket"].(string)
	if code != http.StatusOK || tok == "" {
		t.Fatalf("connect: %d %v", code, out)
	}
	rr := f.do("GET", "/ws/database?cols=80&rows=24&ticket="+tok, "", nil, f.cookie, f.csrf)
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return tg.ID, rr.Code, body
}

// TestDatabaseRefusesForbiddenName: a database target is never probed, so
// the session is the first time its name is looked up. Refused before the
// upgrade, so no container starts.
func TestDatabaseRefusesForbiddenName(t *testing.T) {
	f := newConnectFixture(t)
	f.h.Prober = &target.Prober{}
	id, code, body := redeemDatabase(t, f, "orders-named", "localhost")
	if code != http.StatusUnprocessableEntity || body["code"] != "address_forbidden" {
		t.Fatalf("redeem: %d %v, want 422 address_forbidden", code, body)
	}
	wantAddressRefused(t, f, id, "database")
}

// TestDatabaseRefusesMetadataName: a name that resolves to the IPv6 metadata
// service is refused; so is one that does not resolve at all, since the
// gateway cannot vouch for where the sidecar would connect, but that is a
// lookup failure, not a refused address, and is not audited as one.
func TestDatabaseRefusesMetadataName(t *testing.T) {
	f := newConnectFixture(t)
	f.h.Prober = &target.Prober{Resolver: fakeResolver{"orders.zanskar.invalid": {"fd00:ec2::254"}}}
	id, code, body := redeemDatabase(t, f, "orders-meta", "orders.zanskar.invalid")
	if code != http.StatusUnprocessableEntity || body["code"] != "address_forbidden" {
		t.Fatalf("redeem: %d %v, want 422 address_forbidden", code, body)
	}
	wantAddressRefused(t, f, id, "database")

	_, code, body = redeemDatabase(t, f, "orders-gone", "gone.zanskar.invalid")
	if code != http.StatusConflict || body["code"] != "target_unavailable" {
		t.Fatalf("redeem of a name that does not resolve: %d %v, want 409 target_unavailable", code, body)
	}
	if ev := lastEvent(t, f, "session.connect"); ev.Outcome != audit.Success {
		t.Fatalf("a lookup failure was audited as a refusal: %+v", ev)
	}
}

// TestTerminalDialsTheCheckedAddress: the SSH bridge connects to the address
// the check passed, not to the name. The system resolver could not have found
// this one, and a second lookup is what DNS rebinding exploits.
func TestTerminalDialsTheCheckedAddress(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	r.h.Prober = &target.Prober{AllowLoopback: true, Resolver: fakeResolver{"shell.zanskar.invalid": {"127.0.0.1"}}}
	r.setAddress(t, r.targetID, "shell.zanskar.invalid")
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
}

// TestWinRMDialsTheCheckedAddress: the same for WinRM, whose URL and TLS
// server name keep the target's name while the connection goes to the
// checked address.
func TestWinRMDialsTheCheckedAddress(t *testing.T) {
	r := newWinRMRig(t)
	id := r.winTarget(t, "win-named", "admin", r.wsm.Fingerprint())
	r.h.Prober = &target.Prober{AllowLoopback: true, Resolver: fakeResolver{"win.zanskar.invalid": {"127.0.0.1"}}}
	r.setAddress(t, id, "win.zanskar.invalid")
	ws, _, err := r.open(t, id) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, output, reason := runConsole(t, ctx, ws, nil); reason != "user_exit" || !strings.Contains(output, "ran: Get-Service winrm") {
		t.Fatalf("end %q, output %q", reason, output)
	}
}
