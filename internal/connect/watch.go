// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"time"

	"github.com/coder/websocket"
)

// How often a running session's socket is pinged, how long a pong may take, and
// how many pings in a row may go unanswered before the browser is taken to be gone.
// Variables so a test need not wait a minute.
var (
	pingEvery  = 30 * time.Second
	pingWait   = 15 * time.Second
	pingMissed = 2
)

// watchClient pings the browser while a session runs and closes the socket when
// it stops answering, which ends the session as the person leaving does. A
// browser that vanishes without a close (a laptop that slept, a network that
// dropped) left the session listed as open until the policy's idle timeout, since
// nothing told the gateway: its writes went into a buffer, and a proxy in front
// kept the connection (the owner, 2026-11-05: a session still appears after the
// user has gone). The returned function stops the watch; call it when the bridge
// returns.
//
// A browser answers a ping itself, below the page's scripts, so a tab that is in
// the background or busy still answers. The ping is answered only while the
// socket is being read, which every bridge does until it ends.
func watchClient(ws *websocket.Conn) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
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
				return
			}
			if err == nil {
				missed = 0
				continue
			}
			if missed++; missed >= most {
				_ = ws.CloseNow()
				return
			}
		}
	}()
	return cancel
}
