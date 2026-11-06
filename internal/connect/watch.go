// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"sync/atomic"
	"time"
)

// How often a running session's socket is pinged, how long a pong may take, and
// how many pings in a row may go unanswered before the browser is taken to be
// gone. A tick at 20 s unanswered by 35 s, the next at 40 s unanswered by 55 s:
// a browser that vanished is noticed within a minute. Variables so a test need
// not wait that long.
var (
	pingEvery  = 20 * time.Second
	pingWait   = 15 * time.Second
	pingMissed = 2
)

// clientLostDetail is what a session's row says when the watch ended it. The
// bridge saw the socket close as it does when the person leaves, so the reason
// is user_exit; the detail keeps the two apart in the lists and the audit log.
const clientLostDetail = "the browser stopped answering"

// pinger is what the watch needs of a socket: coder/websocket's Conn, or a fake
// in a test.
type pinger interface {
	Ping(ctx context.Context) error
	CloseNow() error
}

// clientWatch is the watch on one session's socket; see watchClient.
type clientWatch struct {
	cancel context.CancelFunc
	lost   atomic.Bool
}

// Stop ends the watch; call it when the bridge returns.
func (w *clientWatch) Stop() { w.cancel() }

// Lost reports whether the watch closed the socket.
func (w *clientWatch) Lost() bool { return w.lost.Load() }

// watchClient pings the browser while a session runs and closes the socket when
// it stops answering, which ends the session as the person leaving does. A
// browser that vanishes without a close (a laptop that slept, a network that
// dropped) left the session listed as open until the policy's idle timeout,
// since nothing told the gateway: its writes went into a buffer, and a proxy in
// front kept the connection (the owner, 2026-11-05: a session still appears
// after the user has gone).
//
// A browser answers a ping itself, below the page's scripts, so a tab in the
// background or busy still answers. The pong is read by the bridge's own read
// of the socket, so a bridge that has stopped reading misses it too: one
// blocked on a write to a target that stopped taking input. The readers hand
// input on through buffers (an SSH channel's window, a pipe, a channel of
// lines), so that takes a target wedged for the whole minute with input queued
// behind it, and a session so stuck is one to end.
func watchClient(ws pinger) *clientWatch {
	ctx, cancel := context.WithCancel(context.Background())
	w := &clientWatch{cancel: cancel}
	every, wait, most := pingEvery, pingWait, pingMissed // read once: a test changes them
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		missed := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			pctx, done := context.WithTimeout(ctx, wait)
			err := ws.Ping(pctx)
			done()
			if ctx.Err() != nil {
				return // stopped while waiting: the session ended on its own
			}
			if err == nil {
				missed = 0
				continue
			}
			if missed++; missed >= most {
				w.lost.Store(true)
				_ = ws.CloseNow()
				return
			}
		}
	}()
	return w
}
