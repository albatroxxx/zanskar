// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/settings"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/user"
)

// 2026-11-03, idea 7 (ADR 0042 amendment): four eyes for desktops and
// applications, held before guacd draws them, and for every session to a
// target with a four-eyes tag, whichever policy admits it.

// deskFourEyes makes the desktop rig's policy ask for a watcher.
func deskFourEyes(t *testing.T, r *desktopRig) {
	t.Helper()
	p, err := r.h.Policies.Get(r.ctx, r.policyIDs["desk"])
	if err != nil {
		t.Fatal(err)
	}
	p.Grants[0].RequireWatcher = true
	if err := r.h.Policies.Update(r.ctx, p); err != nil {
		t.Fatal(err)
	}
}

// readUntil reads guacamole frames until their text holds want.
func readUntil(t *testing.T, ctx context.Context, ws *websocket.Conn, want string) string {
	t.Helper()
	var seen string
	for !strings.Contains(seen, want) {
		_, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("waiting for %q: %v (got %q)", want, err, seen)
		}
		seen += string(data)
	}
	return seen
}

func TestFourEyesHoldsADesktopBeforeGuacd(t *testing.T) {
	r := newDesktopRig(t)
	deskFourEyes(t, r)
	id := r.addTarget(t, "vnc-box", map[target.Protocol]int{target.VNC: 5900}, "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws, _, err := r.dial(ctx, r.ticket(t, id, "vnc")) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	seen := readUntil(t, ctx, ws, "7.zanskar,7.waiting,")
	if !strings.Contains(seen, "second person") || !strings.HasPrefix(seen, "0.,32.") {
		t.Fatalf("the tunnel opens, then says why it waits: %q", seen)
	}
	live := r.h.Registry.List()
	if len(live) != 1 {
		t.Fatalf("held, the session is live so it can be watched: %d", len(live))
	}
	sid := live[0].SessionID
	// The owner watching themself releases nothing; guacd is not dialled.
	r.h.Registry.Watch(sid, r.alice.ID, +1)
	time.Sleep(300 * time.Millisecond)
	if n := r.accepted.Load(); n != 0 {
		t.Fatalf("guacd dialled %d times before anyone watched", n)
	}
	r.h.Registry.Watch(sid, "auditor-1", +1)
	rest := readUntil(t, ctx, ws, "7.zanskar,4.file,")
	if n := r.accepted.Load(); n != 1 {
		t.Fatalf("guacd dialled %d times once watched, want 1", n)
	}
	if strings.Contains(rest, "0.,32.") {
		t.Fatalf("the tunnel was opened twice: %q", rest)
	}
	if evs, _, _ := r.auditLog.List(ctx, audit.Filter{Action: audit.SessionWatcherWait}); len(evs) != 1 || evs[0].ObjectID != sid {
		t.Fatalf("the wait is audited: %v", evs)
	}
}

// An application under four eyes starts no browser until someone watches.
func TestFourEyesHoldsAnApplicationBeforeItsBrowser(t *testing.T) {
	r, id, calls := appRig(t)
	p, err := r.h.Policies.Get(r.ctx, r.policyIDs["apps"])
	if err != nil {
		t.Fatal(err)
	}
	p.Grants[0].RequireWatcher = true
	if err := r.h.Policies.Update(r.ctx, p); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ws, _, err := r.dial(ctx, r.ticket(t, id, "http")) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	readUntil(t, ctx, ws, "7.zanskar,7.waiting,")
	time.Sleep(300 * time.Millisecond)
	if b, _ := os.ReadFile(calls); strings.Contains(string(b), "run") { // #nosec G304 -- test temp dir
		t.Fatalf("the browser started before anyone watched: %s", b)
	}
	r.h.Registry.Watch(r.h.Registry.List()[0].SessionID, "auditor-1", +1)
	readUntil(t, ctx, ws, "7.zanskar,4.file,")
	if b, _ := os.ReadFile(calls); !strings.Contains(string(b), "run") { // #nosec G304 -- test temp dir
		t.Fatalf("watched, the browser starts: %s", b)
	}
}

func TestFourEyesDesktopNobodyCame(t *testing.T) {
	defer func(w time.Duration) { watchWait = w }(watchWait)
	watchWait = 300 * time.Millisecond
	r := newDesktopRig(t)
	deskFourEyes(t, r)
	id := r.addTarget(t, "vnc-box", map[target.Protocol]int{target.VNC: 5900}, "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws, _, err := r.dial(ctx, r.ticket(t, id, "vnc")) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	readUntil(t, ctx, ws, "nobody watched")
	ev := lastEvent(t, r.connectFixture, "session.end")
	var d map[string]string
	_ = json.Unmarshal(ev.Details, &d)
	if d["reason"] != session.EndNoWatcher {
		t.Fatalf("ended %v", d)
	}
	if n := r.accepted.Load(); n != 0 {
		t.Fatalf("guacd dialled %d times for a session nobody watched", n)
	}
	// No recording was started, so none was registered (session.start
	// names the recording); the wait and the end are on the record.
	if evs, _, _ := r.auditLog.List(ctx, audit.Filter{Action: audit.SessionStart}); len(evs) != 0 {
		t.Fatalf("a session nobody watched registered a recording: %v", evs)
	}
	if evs, _, _ := r.auditLog.List(ctx, audit.Filter{Action: audit.SessionWatcherWait}); len(evs) != 1 || evs[0].ObjectID != ev.ObjectID {
		t.Fatalf("the wait: %v", evs)
	}
	if len(r.h.Registry.List()) != 0 {
		t.Fatal("a session nobody watched stays live")
	}
}

func TestFourEyesByTag(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// A tag the target does not carry: it runs as its policy says.
	r.h.FourEyesTags = func() []settings.FourEyesTag { return []settings.FourEyesTag{{Key: "env", Value: "prod"}} }
	ws, _, err := r.dial(ctx, r.ticket(t)) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	readText(t, ctx, ws, "ready")
	ws.CloseNow()
	// The target's own tag (env=test): held, though no grant asks for it.
	r.h.FourEyesTags = func() []settings.FourEyesTag {
		return []settings.FourEyesTag{{Key: "tier", Value: "web"}, {Key: "env", Value: "test"}}
	}
	ws, _, err = r.dial(ctx, r.ticket(t)) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	readText(t, ctx, ws, "waiting")
	var held string
	for _, l := range r.h.Registry.List() {
		held = l.SessionID
	}
	r.h.Registry.Watch(held, "auditor-1", +1)
	readText(t, ctx, ws, "ready")
}

func TestWatchableAndTagged(t *testing.T) {
	for p, want := range map[target.Protocol]bool{target.SSH: true, target.WinRM: true, target.RDP: true, target.VNC: true, target.HTTP: true, target.Database: false} {
		if watchable(p) != want {
			t.Fatalf("watchable(%s) = %v", p, !want)
		}
	}
	h := &Handler{}
	ep := &endpoint{Tags: map[string]string{"env": "prod", "tier": "web"}}
	if h.fourEyesTagged(ep) {
		t.Fatal("no setting wired names no tag")
	}
	h.FourEyesTags = func() []settings.FourEyesTag {
		return []settings.FourEyesTag{{Key: "env", Value: "staging"}, {Key: "team", Value: "web"}}
	}
	if h.fourEyesTagged(ep) {
		t.Fatal("a key with another value, or a value under another key, is not the tag")
	}
	h.FourEyesTags = func() []settings.FourEyesTag {
		return []settings.FourEyesTag{{Key: "env", Value: "staging"}, {Key: "tier", Value: "web"}}
	}
	if !h.fourEyesTagged(ep) {
		t.Fatal("any one tag is enough")
	}
}

// A watcher of a held desktop is counted at once, which releases it, waits
// with the console's tunnel kept open, and joins guacd as soon as the
// session has dialled it.
func TestWatchingAHeldDesktopJoinsWhenItStarts(t *testing.T) {
	defer func(p, b time.Duration) { heldPoll, heldBeat = p, b }(heldPoll, heldBeat)
	heldPoll, heldBeat = 20*time.Millisecond, 50*time.Millisecond
	e := newShadowEnv(t)
	auditor := e.cookieFor(t, "auditor", user.RoleAuditor)
	addr, got := joinRecorder(t)
	e.h.GuacdAddr = func() string { return addr }
	e.reg.Add(context.Background(), gateway.Live{SessionID: "d2", UserID: "owner", TargetID: "t1", Protocol: "rdp"})
	ws, code := dialShadow(t, e, "d2", auditor)
	if ws == nil {
		t.Fatalf("watching a held desktop: %d", code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	readUntil(t, ctx, ws, "7.zanskar,7.waiting,")
	if !e.reg.Watched("d2") {
		t.Fatal("the watcher is counted before the desktop starts")
	}
	readUntil(t, ctx, ws, "3.nop;")
	e.reg.SetGuacID("d2", "$conn-7")
	select {
	case req := <-got:
		if req[0] != "$conn-7" || req[1] != "true" {
			t.Fatalf("joined %q read-only=%q", req[0], req[1])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("guacd was never asked to join")
	}
}

func TestWatchingAHeldDesktopThatEnds(t *testing.T) {
	defer func(p time.Duration) { heldPoll = p }(heldPoll)
	heldPoll = 20 * time.Millisecond
	e := newShadowEnv(t)
	auditor := e.cookieFor(t, "auditor", user.RoleAuditor)
	e.h.GuacdAddr = func() string { return "127.0.0.1:1" }
	e.reg.Add(context.Background(), gateway.Live{SessionID: "d3", UserID: "owner", TargetID: "t1", Protocol: "vnc"})
	ws, code := dialShadow(t, e, "d3", auditor)
	if ws == nil {
		t.Fatalf("dial: %d", code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	readUntil(t, ctx, ws, "7.zanskar,7.waiting,")
	e.reg.Remove("d3")
	readUntil(t, ctx, ws, "ended before it started")
}
