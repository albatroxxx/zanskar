// SPDX-License-Identifier: Apache-2.0

// wsclient: drives a Zanskar terminal WebSocket for smoke tests.
// usage: wsclient <ws-url>  ; sends "hello", waits for HELLO, sends exit, prints the end frame.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/coder/websocket"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, os.Args[1], nil) //nolint:bodyclose // library closes the handshake body
	if err != nil {
		fmt.Println("dial error:", err)
		cancel()
		os.Exit(1) //nolint:gocritic // cancel called explicitly above
	}
	defer ws.CloseNow()
	var out strings.Builder
	send := func(m map[string]any) {
		b, _ := json.Marshal(m)
		_ = ws.Write(ctx, websocket.MessageText, b)
	}
	sentHello, sentExit := false, false
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			fmt.Println("read ended:", err)
			break
		}
		if typ == websocket.MessageBinary {
			out.Write(data)
			if !sentHello && strings.Contains(out.String(), "$ ") {
				sentHello = true
				send(map[string]any{"t": "i", "d": "hello\r"})
			}
			if sentHello && !sentExit && strings.Contains(out.String(), "HELLO") {
				sentExit = true
				send(map[string]any{"t": "i", "d": "exit\r"})
			}
			continue
		}
		fmt.Println("control:", string(data))
		if strings.Contains(string(data), `"end"`) {
			break
		}
	}
	fmt.Printf("terminal output (%d bytes) contains HELLO: %v\n", out.Len(), strings.Contains(out.String(), "HELLO"))
}
