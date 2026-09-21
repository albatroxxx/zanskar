// SPDX-License-Identifier: Apache-2.0

package guac

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fakeJoinGuacd accepts a select with a connection id and reports the
// read-only argument it received, then emits a few display instructions.
func fakeJoinGuacd(t *testing.T, gotReadOnly chan<- string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				rd := NewReader(c)
				sel, err := rd.Read()
				if err != nil || sel.Opcode != "select" {
					return
				}
				if !strings.HasPrefix(sel.Args[0], "$") {
					_, _ = c.Write([]byte(Encode("error", "unknown connection", "512")))
					return
				}
				names := []string{"VERSION_1_5_0", "read-only", "hostname"}
				_, _ = c.Write([]byte(Encode("args", names...)))
				for {
					in, err := rd.Read()
					if err != nil {
						return
					}
					if in.Opcode == "connect" {
						gotReadOnly <- in.Args[1]
						break
					}
				}
				_, _ = c.Write([]byte(Encode("ready", "$joined")))
				_, _ = c.Write([]byte(Encode("size", "0", "800", "600")))
				_, _ = c.Write([]byte(Encode("sync", "1")))
				for {
					in, err := rd.Read()
					if err != nil || in.Opcode == "disconnect" {
						return
					}
					_, _ = c.Write([]byte(Encode("echo", in.Opcode)))
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestJoinReadOnly(t *testing.T) {
	got := make(chan string, 1)
	addr := fakeJoinGuacd(t, got)
	c, err := Join(context.Background(), addr, "$conn-1", 800, 600, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.ID != "$joined" {
		t.Fatalf("id %q", c.ID)
	}
	if ro := <-got; ro != "true" {
		t.Fatalf("read-only arg %q", ro)
	}
	if _, err := Join(context.Background(), addr, "rdp", 0, 0, time.Second); err == nil {
		t.Fatal("a protocol name must be rejected as a join target")
	}
}

func TestRelayForwardsDisplayAndFiltersInput(t *testing.T) {
	got := make(chan string, 1)
	addr := fakeJoinGuacd(t, got)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		c, err := Join(r.Context(), addr, "$conn-1", 800, 600, 2*time.Second)
		if err != nil {
			t.Errorf("join: %v", err)
			return
		}
		defer c.Close()
		_ = Relay(r.Context(), c, ws)
		_ = ws.Close(websocket.StatusNormalClosure, "")
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil) //nolint:bodyclose // library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	<-got
	read := func() string {
		_, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	if a := read(); a != Encode("size", "0", "800", "600") {
		t.Fatalf("first frame %q", a)
	}
	if b := read(); b != Encode("sync", "1") {
		t.Fatalf("second frame %q", b)
	}
	// Input is dropped; sync is forwarded and echoed by the fake.
	_ = ws.Write(ctx, websocket.MessageText, []byte(Encode("key", "65", "1")))
	_ = ws.Write(ctx, websocket.MessageText, []byte(Encode("sync", "1")))
	if e := read(); e != Encode("echo", "sync") {
		t.Fatalf("expected only sync to reach guacd, got %q", e)
	}
}
