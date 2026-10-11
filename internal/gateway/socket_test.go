// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// TestCloseAfterEnd: the socket closes normally, carrying the end reason. A
// browser that answers the close ends the bridge's reader at once; one that
// has stopped reading is dropped after the grace, so it cannot hold a
// finished session open, and still finds the close waiting when it reads.
func TestCloseAfterEnd(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers bool
	}{{"answered", true}, {"unanswered", false}} {
		t.Run(tc.name, func(t *testing.T) {
			readerDone := make(chan time.Duration, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
				if err != nil {
					return
				}
				defer ws.CloseNow()
				// The bridge's reader, on the socket's own context.
				wsCtx, wsCancel := context.WithCancel(context.Background())
				read := make(chan struct{})
				go func() {
					defer close(read)
					_, _, _ = ws.Read(wsCtx)
				}()
				start := time.Now()
				CloseAfterEnd(ws, "admin_terminated", wsCancel)
				<-read
				readerDone <- time.Since(start)
			}))
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil) //nolint:bodyclose // the library closes the handshake body
			if err != nil {
				t.Fatal(err)
			}
			defer ws.CloseNow()

			var took time.Duration
			wait := func() {
				select {
				case took = <-readerDone:
				case <-ctx.Done():
					t.Fatal("the bridge's reader never ended")
				}
			}
			if tc.answers {
				_, _, err = ws.Read(ctx)
				wait()
			} else {
				wait()
				_, _, err = ws.Read(ctx)
			}
			var ce websocket.CloseError
			if !errors.As(err, &ce) || ce.Code != websocket.StatusNormalClosure || ce.Reason != "admin_terminated" {
				t.Fatalf("the browser read %v, want a normal close with the end reason", err)
			}
			if tc.answers && took >= closeGrace {
				t.Fatalf("an answered close held the reader for %v", took)
			}
			if !tc.answers && (took < closeGrace*9/10 || took > closeGrace+3*time.Second) {
				t.Fatalf("an unanswered close held the reader for %v, want about %v", took, closeGrace)
			}
		})
	}
}
