// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/session"
)

// fakeSocket answers pings as scripted and notes when it is closed. The watch
// is judged by what it did after so many pings, not by how long a real pong
// took, so nothing here depends on the scheduler: the earlier rig's 40 ms pong
// deadline failed whenever CI starved the client's goroutine for two pings.
type fakeSocket struct {
	answer func(n int, ctx context.Context) error // the nth ping's result
	pinged chan int
	closed chan struct{}
	once   sync.Once
	n      int // the watch is the only caller of Ping
}

func newFakeSocket(answer func(n int, ctx context.Context) error) *fakeSocket {
	return &fakeSocket{answer: answer, pinged: make(chan int, 1024), closed: make(chan struct{})}
}

func (f *fakeSocket) Ping(ctx context.Context) error {
	f.n++
	err := f.answer(f.n, ctx)
	f.pinged <- f.n
	return err
}

func (f *fakeSocket) CloseNow() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

// isClosed reports whether the fake has been closed, without waiting.
func (f *fakeSocket) isClosed() bool {
	select {
	case <-f.closed:
		return true
	default:
		return false
	}
}

// setPings sets the watch's tick and pong wait for one test; the fakes answer
// at once, so the tick is the only wait. The misses allowed stay as shipped.
func setPings(t *testing.T, every, wait time.Duration) {
	t.Helper()
	oe, ow := pingEvery, pingWait
	pingEvery, pingWait = every, wait
	t.Cleanup(func() { pingEvery, pingWait = oe, ow })
}

// waitPings waits for the fake to have been pinged at least n times.
func waitPings(t *testing.T, f *fakeSocket, n int) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case k := <-f.pinged:
			if k >= n {
				return
			}
		case <-deadline:
			t.Fatalf("fewer than %d pings in 10 s", n)
		}
	}
}

// TestWatchClientClosesAfterMissedPings (live, 2026-11-05): a browser that
// vanished without a close left its session open. One that misses pingMissed
// pings in a row is taken to be gone: the socket is closed after exactly that
// many, and the watch says it was the one that closed it.
func TestWatchClientClosesAfterMissedPings(t *testing.T) {
	setPings(t, time.Millisecond, time.Second)
	f := newFakeSocket(func(int, context.Context) error { return errors.New("no pong") })
	w := watchClient(f)
	defer w.Stop()
	select {
	case <-f.closed:
	case <-time.After(10 * time.Second):
		t.Fatal("a client that never answered a ping kept its socket")
	}
	if !w.Lost() {
		t.Fatal("the watch closed the socket and does not say so")
	}
	// Both pings were reported before the close, and none follows it.
	n := 0
	for len(f.pinged) > 0 {
		<-f.pinged
		n++
	}
	if n != pingMissed {
		t.Fatalf("%d pings before the close, want %d", n, pingMissed)
	}
}

// TestWatchClientAnAnswerResetsTheCount: misses that do not run in a row never
// close the socket. A pong that was late once is not a browser that is gone.
func TestWatchClientAnAnswerResetsTheCount(t *testing.T) {
	setPings(t, time.Millisecond, time.Second)
	f := newFakeSocket(func(n int, _ context.Context) error {
		if n%2 == 1 {
			return errors.New("late")
		}
		return nil
	})
	w := watchClient(f)
	defer w.Stop()
	waitPings(t, f, 40)
	if f.isClosed() || w.Lost() {
		t.Fatal("a client that answered every other ping was closed")
	}
}

// TestWatchClientLeavesAnAnsweringClient: a client that answers every ping, as
// a browser does, keeps its socket.
func TestWatchClientLeavesAnAnsweringClient(t *testing.T) {
	setPings(t, time.Millisecond, time.Second)
	f := newFakeSocket(func(int, context.Context) error { return nil })
	w := watchClient(f)
	defer w.Stop()
	waitPings(t, f, 40)
	if f.isClosed() || w.Lost() {
		t.Fatal("a client that answered its pings was closed")
	}
}

// TestWatchClientStops: once stopped, as when the session ends, the watch ends
// the ping it was waiting on and leaves even a client that never answers alone.
func TestWatchClientStops(t *testing.T) {
	setPings(t, time.Millisecond, time.Minute) // a pong may take a minute: only Stop ends the wait
	waiting := make(chan struct{}, 1)
	f := newFakeSocket(func(_ int, ctx context.Context) error {
		waiting <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	})
	w := watchClient(f)
	<-waiting // the first ping is in flight, waiting for a pong that never comes
	w.Stop()
	select {
	case <-f.pinged:
	case <-time.After(10 * time.Second):
		t.Fatal("a stopped watch kept waiting for its pong")
	}
	if f.isClosed() || w.Lost() {
		t.Fatal("a stopped watch closed the socket")
	}
}

// TestWatchClientEndsTheReadOfAQuietBrowser: against a real socket, a client
// that never reads never answers a ping (the side that reads sends the pong),
// so the watch closes the socket and the server's read of it, a bridge's, ends.
// The one test here on a real socket; the client cannot answer, so a slow
// machine makes it slower, never wrong, and the bound is generous.
func TestWatchClientEndsTheReadOfAQuietBrowser(t *testing.T) {
	setPings(t, 20*time.Millisecond, 200*time.Millisecond)
	ended, started := make(chan struct{}), make(chan struct{})
	var w *clientWatch
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(rw, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		w = watchClient(ws)
		close(started)
		defer w.Stop()
		for { // what a bridge does: read until the socket ends
			if _, _, err := ws.Read(r.Context()); err != nil {
				close(ended)
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil) //nolint:bodyclose
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	<-started
	select {
	case <-ended:
	case <-time.After(20 * time.Second):
		t.Fatal("a client that never answered a ping kept its socket")
	}
	if !w.Lost() {
		t.Fatal("the watch closed the socket and does not say so")
	}
}

// TestSessionEndedByTheWatchSaysSo: a terminal session whose browser stops
// answering ends as the person leaving does, user_exit, and its row and its end
// event say the browser stopped answering, so a reader of the audit log can
// tell a person who left from a browser that was lost. Once the bridge has
// named the session it is registered, so it no longer counts as starting.
func TestSessionEndedByTheWatchSaysSo(t *testing.T) {
	setPings(t, 20*time.Millisecond, 200*time.Millisecond)
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ws, _, err := r.dial(ctx, r.ticket(t)) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	// Read until the bridge names the session, then read no more: a browser
	// that reads nothing answers no ping.
	var sessionID string
	for sessionID == "" {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if typ != websocket.MessageText {
			continue
		}
		var c termFrame
		_ = json.Unmarshal(data, &c)
		if c.T == "ready" {
			sessionID = c.SessionID
		}
	}
	if r.h.Starting(sessionID) {
		t.Fatal("a registered session still counts as starting")
	}
	var s *session.Session
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if s, err = r.h.Sessions.Get(ctx, sessionID); err != nil {
			t.Fatal(err)
		}
		if s.EndedAt != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the session of a browser that stopped answering was not ended")
		}
	}
	if s.EndReason != session.EndUserExit || s.EndDetail != clientLostDetail {
		t.Fatalf("ended as %q %q, want %q %q", s.EndReason, s.EndDetail, session.EndUserExit, clientLostDetail)
	}
	var details string
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		err := r.db.QueryRowContext(ctx, `SELECT details FROM audit_events WHERE action = 'session.end' AND object_id = ?`, sessionID).Scan(&details)
		if err == nil || time.Now().After(deadline) {
			break
		}
	}
	if !strings.Contains(details, clientLostDetail) {
		t.Fatalf("the end event %q says nothing of the browser", details)
	}
}
