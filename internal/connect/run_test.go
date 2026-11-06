// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/ticket"
)

// TestStartingUntilRegisteredOrEnded: a session counts as this gateway's from
// its row, before its bridge registers (a dial, an image pull of minutes), until
// its row ends, and not for ever: the sweep must neither end a session still
// being set up nor keep one a run left behind. A later start forgets the one
// left behind.
func TestStartingUntilRegisteredOrEnded(t *testing.T) {
	f := newConnectFixture(t)
	f.h.starting.m.Store("left-behind", time.Now().Add(-startingFor))
	g := &ticket.Grant{UserID: f.alice.ID, Protocol: "ssh"}
	ep := &endpoint{TargetID: f.ids["ok"], LiveKey: f.ids["ok"]}
	run, ok := f.h.startRun(httptest.NewRequest("GET", "/ws/ssh", nil), nil, g, ep, "203.0.113.5")
	if !ok {
		t.Fatal("startRun refused a session")
	}
	if !f.h.Starting(run.s.ID) {
		t.Fatal("a session whose row is written does not count as starting")
	}
	if f.h.Starting("left-behind") {
		t.Fatal("a session left behind past startingFor still counts as starting")
	}
	if _, held := f.h.starting.m.Load("left-behind"); held {
		t.Fatal("the session left behind was not forgotten at the next start")
	}
	run.endRow(run.s.ID, session.EndUserExit, "")
	if f.h.Starting(run.s.ID) {
		t.Fatal("an ended session still counts as starting")
	}
}

// closedRecording is a recording whose close has nothing left to flush.
type closedRecording struct{}

func (closedRecording) Close() (int64, string, error) { return 1, "sha256:00", nil }

// TestClosingWritesAreBounded: the writes that close a session outlive its
// request, but not for ever. With the database stuck, here SQLite's one
// connection held by an open transaction, ending the row and finishing the
// recording give up after the close timeout. They used to wait without a
// deadline, holding the bridge's goroutine as long as the database (D12).
func TestClosingWritesAreBounded(t *testing.T) {
	f := newConnectFixture(t)
	f.h.CloseTimeout = 100 * time.Millisecond
	s := &session.Session{UserID: f.alice.ID, TargetID: f.ids["ok"], Protocol: "ssh", ClientIP: "203.0.113.5"}
	if err := f.h.Sessions.Start(f.ctx, s); err != nil {
		t.Fatal(err)
	}
	run := &sessionRun{h: f.h, r: httptest.NewRequest("GET", "/ws/ssh", nil), s: s}

	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		run.endRow(s.ID, session.EndError, "")
		run.finishRecording(closedRecording{}, &session.Recording{ID: "r1", SessionID: s.ID})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("the closing writes waited on a stuck database past their deadline")
	}
	_ = tx.Rollback()
	<-done
}
