// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/gateway/guac"
	"github.com/albatroxxx/zanskar/internal/target"
)

// The other tests' targets mostly have no listener; they pass the pre-flight.
// TestPreflight below dials for real.
func init() {
	defaultPreflightDial = func(context.Context, string) error { return nil }
}

// 2026-11-03 live audit, idea 2: a host that did not answer opened a desktop
// that drew nothing and ended as "target lost", six times in three minutes.
// The pre-flight refuses it at Connect, in words, before any session starts.
func TestPreflight(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	open := ln.Addr().(*net.TCPAddr).Port
	// A port nothing listens on: listen, note it, close.
	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l2.Addr().(*net.TCPAddr).Port
	_ = l2.Close()

	h := &Handler{Prober: &target.Prober{AllowLoopback: true}, PreflightDial: dialTCP, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ep := func(port int) *endpoint {
		return &endpoint{Name: "win-1", Address: "127.0.0.1", Ports: map[target.Protocol]int{target.RDP: port, target.SSH: port}}
	}

	if code, msg := h.preflight(context.Background(), ep(open), target.RDP); code != "" {
		t.Fatalf("a host that answers: %s %s", code, msg)
	}
	code, msg := h.preflight(context.Background(), ep(closed), target.RDP)
	if code != "target_unreachable" || !strings.Contains(msg, "win-1 refused the connection on port "+strconv.Itoa(closed)) {
		t.Fatalf("a closed port: %q %q", code, msg)
	}
	// Databases and applications start their own containers: no pre-flight.
	if code, _ := h.preflight(context.Background(), ep(closed), target.Database); code != "" {
		t.Fatalf("a database session is not pre-flighted: %q", code)
	}
	if code, _ := h.preflight(context.Background(), ep(closed), target.HTTP); code != "" {
		t.Fatalf("an application session is not pre-flighted: %q", code)
	}

	// The address rules apply as for a session: a forbidden address is not
	// dialled at all.
	dialled := false
	strict := &Handler{Prober: &target.Prober{}, PreflightDial: func(context.Context, string) error { dialled = true; return nil }, Log: h.Log}
	if code, _ := strict.preflight(context.Background(), ep(open), target.SSH); code != "address_forbidden" || dialled {
		t.Fatalf("loopback without the exception: %q, dialled %v", code, dialled)
	}
}

// Connect refuses a host that does not answer, in words the console shows,
// audits the refusal, and issues no ticket; a name that resolves somewhere
// forbidden is refused there too, with the address rule's own answer.
func TestConnectPreflightRefuses(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	r.h.PreflightDial = func(context.Context, string) error { return syscall.ECONNREFUSED }
	code, out := r.postConnect(t, r.url, r.targetID, "ssh")
	if code != 409 || out["code"] != "target_unreachable" || out["ticket"] != nil || !strings.Contains(out["message"].(string), "refused the connection on port") {
		t.Fatalf("an unanswering host: %d %v", code, out)
	}
	ev := lastEvent(t, r.connectFixture, "session.connect")
	if !strings.Contains(string(ev.Details), `"reason":"target_unreachable"`) {
		t.Fatalf("refusal audited as %s", ev.Details)
	}

	r.h.PreflightDial = nil
	r.h.Prober = &target.Prober{}
	r.setAddress(t, r.targetID, "localhost")
	code, out = r.postConnect(t, r.url, r.targetID, "ssh")
	if code != 422 || out["code"] != "address_forbidden" {
		t.Fatalf("a forbidden name at Connect: %d %v", code, out)
	}
}

// An RDP host that was down answered "the target's certificate does not
// match the pinned fingerprint": the pin check is what first failed to reach
// it. It is target_unavailable now, and no mismatch is audited.
func TestDesktopUnreachableIsNotAMismatch(t *testing.T) {
	r := newDesktopRig(t)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	id := r.addTarget(t, "rdp-down", map[target.Protocol]int{target.RDP: closed}, strings.Repeat("ab", 32))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws, _, err := r.dial(ctx, r.ticket(t, id, "rdp")) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	if words := refusedOverSocket(t, ws); words != guac.ErrorInstruction("could not reach the target to check its certificate", guac.StatusSessionClosed) {
		t.Fatalf("refused with %q, want a guacamole error saying the target could not be reached", words)
	}
	if evs, _, _ := r.h.Audit.List(ctx, audit.Filter{Action: "target.tls.mismatch"}); len(evs) != 0 {
		t.Fatalf("a host that was down was audited as a certificate mismatch: %v", evs)
	}
}

func TestUnreachableMsg(t *testing.T) {
	for err, want := range map[error]string{
		syscall.ECONNREFUSED:     "box refused the connection on port 3389",
		context.DeadlineExceeded: "box did not answer on port 3389 within 4 seconds",
		syscall.EHOSTUNREACH:     "box cannot be reached from the gateway",
		io.EOF:                   "box did not take a connection on port 3389",
	} {
		if got := unreachableMsg("box", 3389, err); !strings.HasPrefix(got, want) {
			t.Errorf("%v: %q, want it to start %q", err, got, want)
		}
	}
}
