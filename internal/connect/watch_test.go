// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// watchRig serves one socket, watched, and reports when the server's read of it
// fails: the bridge reading the socket ending, which ends the session. With
// stopAtOnce the watch is stopped as soon as it starts, as when a session ends.
func watchRig(t *testing.T, stopAtOnce bool) (client *websocket.Conn, readEnded <-chan struct{}) {
	t.Helper()
	oe, ow, om := pingEvery, pingWait, pingMissed
	pingEvery, pingWait, pingMissed = 20*time.Millisecond, 40*time.Millisecond, 2
	ended, started := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		stop := watchClient(ws)
		close(started) // the watch has read its settings: the test may change them back
		defer stop()
		if stopAtOnce {
			stop()
		}
		// What a bridge does: read until the socket ends.
		for {
			if _, _, err := ws.Read(r.Context()); err != nil {
				close(ended)
				return
			}
		}
	}))
	t.Cleanup(func() {
		srv.Close()
		pingEvery, pingWait, pingMissed = oe, ow, om
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil) //nolint:bodyclose
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	<-started
	return c, ended
}

// TestWatchClientClosesAfterAClientGoesQuiet (live, 2026-11-05): a browser that
// vanished without a close left its session open. One that never answers a
// ping is taken to be gone, and the socket is closed, which ends the bridge.
func TestWatchClientClosesAfterAClientGoesQuiet(t *testing.T) {
	_, ended := watchRig(t, false) // the client never reads, so it never answers a ping
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("a client that never answered a ping kept its socket")
	}
}

// TestWatchClientLeavesAnAnsweringClient: a client that reads, as a browser does,
// answers every ping and keeps its socket far longer than the pings would allow.
func TestWatchClientLeavesAnAnsweringClient(t *testing.T) {
	c, ended := watchRig(t, false)
	go func() {
		for {
			if _, _, err := c.Read(t.Context()); err != nil {
				return
			}
		}
	}()
	select {
	case <-ended:
		t.Fatal("a client that answered its pings was closed")
	case <-time.After(600 * time.Millisecond): // thirty ping intervals
	}
}

// TestWatchClientStops: once stopped, as when the session ends, the watch leaves
// even a client that never answers alone.
func TestWatchClientStops(t *testing.T) {
	_, ended := watchRig(t, true)
	select {
	case <-ended:
		t.Fatal("a stopped watch closed the socket")
	case <-time.After(600 * time.Millisecond):
	}
}
