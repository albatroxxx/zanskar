// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/session"
)

// fourEyes makes the fixture's test-all policy ask for a second person
// watching on its host grant (ADR 0042).
func fourEyes(t *testing.T, f *connectFixture) {
	t.Helper()
	p, err := f.h.Policies.Get(f.ctx, f.policyIDs["test-all"])
	if err != nil {
		t.Fatal(err)
	}
	p.Grants[0].RequireWatcher = true
	if err := f.h.Policies.Update(f.ctx, p); err != nil {
		t.Fatal(err)
	}
}

// readText reads text frames until one whose "t" is want, or fails.
func readText(t *testing.T, ctx context.Context, ws *websocket.Conn, want string) map[string]string {
	t.Helper()
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("waiting for %q: %v", want, err)
		}
		if typ != websocket.MessageText {
			continue
		}
		var m map[string]string
		_ = json.Unmarshal(data, &m)
		if m["t"] == want {
			return m
		}
	}
}

// 2026-11-03, idea 7: a session under a four-eyes grant is held, told why,
// until someone other than its owner watches; then it runs.
func TestFourEyesHoldsUntilWatched(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	fourEyes(t, r.connectFixture)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws, _, err := r.dial(ctx, r.ticket(t)) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	if m := readText(t, ctx, ws, "waiting"); !strings.Contains(m["msg"], "second person") {
		t.Fatalf("waiting: %v", m)
	}
	live := r.h.Registry.List()
	if len(live) != 1 {
		t.Fatalf("live sessions: %d", len(live))
	}
	sid := live[0].SessionID
	// The owner watching themself releases nothing.
	r.h.Registry.Watch(sid, r.alice.ID, +1)
	short, stop := context.WithTimeout(ctx, 300*time.Millisecond)
	if _, _, err := ws.Read(short); err == nil {
		t.Fatal("the session went on with only its owner watching")
	}
	stop()
	// A failed read closes a coder websocket; dial again for the release.
	ws.CloseNow()
	r.h.Registry.Watch(sid, "auditor-1", +1)
	if evs, _, _ := r.auditLog.List(ctx, audit.Filter{Action: audit.SessionWatcherWait}); len(evs) != 1 || evs[0].ObjectID != sid {
		t.Fatalf("the wait is audited: %v", evs)
	}
}

// Released by a watcher, the session runs: ready arrives.
func TestFourEyesReleasedByAWatcher(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	fourEyes(t, r.connectFixture)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws, _, err := r.dial(ctx, r.ticket(t)) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	readText(t, ctx, ws, "waiting")
	r.h.Registry.Watch(r.h.Registry.List()[0].SessionID, "auditor-1", +1)
	readText(t, ctx, ws, "ready")
}

// Nobody in time: the session ends no_watcher, saying why, and keeps no
// recording of nothing.
func TestFourEyesNobodyCame(t *testing.T) {
	defer func(w time.Duration) { watchWait = w }(watchWait)
	watchWait = 200 * time.Millisecond
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	fourEyes(t, r.connectFixture)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws, _, err := r.dial(ctx, r.ticket(t)) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	readText(t, ctx, ws, "waiting")
	for {
		_, _, err := ws.Read(ctx)
		if err == nil {
			continue
		}
		var ce websocket.CloseError
		if !errors.As(err, &ce) || ce.Code != websocket.StatusPolicyViolation || !strings.Contains(ce.Reason, "nobody watched") {
			t.Fatalf("closed with %v, want a refusal saying nobody watched", err)
		}
		break
	}
	ev := lastEvent(t, r.connectFixture, "session.end")
	var d map[string]string
	_ = json.Unmarshal(ev.Details, &d)
	if d["reason"] != session.EndNoWatcher {
		t.Fatalf("ended %v", d)
	}
}

// A grant asking for four eyes admits no session that cannot be held:
// refused at Connect rather than run unwatched.
func TestFourEyesRefusesWhatCannotBeHeld(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	fourEyes(t, r.connectFixture)
	code, out := r.postConnect(t, r.url, r.targetID, "rdp")
	if code != http.StatusConflict || out["code"] != "watcher_unavailable" {
		t.Fatalf("rdp under four eyes: %d %v", code, out)
	}
}
