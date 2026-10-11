// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"time"

	"github.com/coder/websocket"
)

// closeGrace is how long a browser has to answer the close that follows a
// session's end frame before its connection is dropped. A live browser
// answers within a round trip.
const closeGrace = time.Second

// CloseAfterEnd closes a bridge's browser socket normally once the bridge has
// sent the frame saying why the session ended, so the console sees an orderly
// close rather than a lost connection. The close handshake waits for the
// browser's answer; a browser that has stopped reading is cut off after
// closeGrace by stopIO, the cancel of the context the bridge reads and writes
// the socket under (coder/websocket drops the connection when the context of
// a pending read is cancelled). It returns at once, so recording how the
// session ended never waits on the browser, and a later Close by the caller
// waits for this one to finish.
func CloseAfterEnd(ws *websocket.Conn, reason string, stopIO context.CancelFunc) {
	t := time.AfterFunc(closeGrace, stopIO)
	go func() {
		_ = ws.Close(websocket.StatusNormalClosure, reason)
		t.Stop()
		stopIO()
	}()
}
