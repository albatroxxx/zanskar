// SPDX-License-Identifier: Apache-2.0

// wsclient: drives a Zanskar terminal WebSocket for smoke tests.
// usage: wsclient <ws-url> [prompt] [command] [expect]
// Waits for the prompt (default "$ "), sends the command (default "hello"), waits for expect
// (default "HELLO"), sends exit, and prints the end frame. Real shells use for example
// `wsclient <url> '$ ' 'echo HEL""LO' HELLO` and PowerShell `wsclient <url> '> ' 'echo HEL""LO' HELLO`.
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
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if len(os.Args) < 2 {
		fmt.Println("usage: wsclient <ws-url> [prompt] [command] [expect]")
		cancel()
		os.Exit(2) //nolint:gocritic // cancel called explicitly above
	}
	prompt, command, expect := "$ ", "hello", "HELLO"
	if len(os.Args) > 2 {
		prompt = os.Args[2]
	}
	if len(os.Args) > 3 {
		command = os.Args[3]
	}
	if len(os.Args) > 4 {
		expect = os.Args[4]
	}
	ws, _, err := websocket.Dial(ctx, os.Args[1], nil)
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
			if !sentHello && strings.Contains(out.String(), prompt) {
				sentHello = true
				send(map[string]any{"t": "i", "d": command + "\r"})
			}
			if sentHello && !sentExit && strings.Contains(out.String(), expect) {
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
	fmt.Printf("terminal output (%d bytes) contains %s: %v\n", out.Len(), expect, strings.Contains(out.String(), expect))
}
