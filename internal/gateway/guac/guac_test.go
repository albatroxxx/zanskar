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

func TestEncodeParseRoundTrip(t *testing.T) {
	raw := Encode("connect", "héllo", "", "a,b;c", "日本語")
	if raw != "7.connect,5.héllo,0.,5.a,b;c,3.日本語;" {
		t.Fatalf("encode: %q", raw)
	}
	in, err := Parse(raw)
	if err != nil || in.Opcode != "connect" || len(in.Args) != 4 || in.Args[0] != "héllo" || in.Args[2] != "a,b;c" || in.Args[3] != "日本語" {
		t.Fatalf("parse: %+v %v", in, err)
	}
	if Opcode(raw) != "connect" {
		t.Fatal("opcode")
	}
	for _, bad := range []string{"", "x", "3.abc", "abc;", "9.ab;", "-1.a;", "2.ab,x;"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
	rd := NewReader(strings.NewReader("6.select,3.rdp;4.size,4.1024,3.768,2.96;"))
	a, _ := rd.ReadRaw()
	b, _ := rd.ReadRaw()
	if a != "6.select,3.rdp;" || b != "4.size,4.1024,3.768,2.96;" {
		t.Fatalf("stream: %q %q", a, b)
	}
	if _, err := rd.ReadRaw(); err == nil {
		t.Fatal("expected EOF")
	}
	if _, err := NewReader(strings.NewReader("99999999.x")).ReadRaw(); err == nil {
		t.Fatal("expected limit error")
	}
}

// fakeGuacd performs the server side of the handshake, then echoes every
// instruction back with opcode "echo" until it reads "disconnect".
func fakeGuacd(t *testing.T, gotParams chan<- map[string]string) string {
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
				names := []string{"VERSION_1_5_0", "hostname", "port", "username", "password"}
				_, _ = c.Write([]byte(Encode("args", names...)))
				params := map[string]string{}
				for {
					in, err := rd.Read()
					if err != nil {
						return
					}
					if in.Opcode == "connect" {
						for i, n := range names {
							if i < len(in.Args) {
								params[n] = in.Args[i]
							}
						}
						break
					}
					params["_"+in.Opcode] = strings.Join(in.Args, "|")
				}
				if gotParams != nil {
					gotParams <- params
				}
				if params["password"] == "refuse" {
					_, _ = c.Write([]byte(Encode("error", "Connection refused by test", "519")))
					return
				}
				_, _ = c.Write([]byte(Encode("ready", "$conn-1")))
				for {
					in, err := rd.Read()
					if err != nil || in.Opcode == "disconnect" {
						return
					}
					_, _ = c.Write([]byte(Encode("echo", append([]string{in.Opcode}, in.Args...)...)))
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestDialHandshake(t *testing.T) {
	got := make(chan map[string]string, 2)
	addr := fakeGuacd(t, got)
	p := Params{Protocol: "rdp", Args: map[string]string{"hostname": "10.0.0.5", "port": "3389", "username": "u", "password": "p"}, Width: 1280, Height: 800, Audio: []string{"audio/L16"}, Timezone: "Asia/Kolkata"}
	c, err := Dial(context.Background(), addr, p, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.ID != "$conn-1" {
		t.Fatalf("id %q", c.ID)
	}
	params := <-got
	if params["hostname"] != "10.0.0.5" || params["password"] != "p" || params["VERSION_1_5_0"] != "VERSION_1_5_0" {
		t.Fatalf("params %v", params)
	}
	if params["_size"] != "1280|800|96" || params["_audio"] != "audio/L16" || params["_timezone"] != "Asia/Kolkata" {
		t.Fatalf("pre-connect instructions: %v", params)
	}
	if _, err := Dial(context.Background(), addr, Params{Protocol: "rdp", Args: map[string]string{"password": "refuse"}}, 2*time.Second); err == nil || !strings.Contains(err.Error(), "refused by test") {
		t.Fatalf("expected guacd error, got %v", err)
	}
	if _, err := Dial(context.Background(), addr, Params{Protocol: "telnet"}, time.Second); err == nil {
		t.Fatal("unsupported protocol must fail")
	}
}

func TestBridgeRelayAndPolicy(t *testing.T) {
	addr := fakeGuacd(t, nil)
	reasonCh := make(chan string, 1)
	var recorded []string
	rec := recFunc(func(raw string) error { recorded = append(recorded, raw); return nil })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		c, err := Dial(r.Context(), addr, Params{Protocol: "vnc", Args: map[string]string{}}, 2*time.Second)
		if err != nil {
			t.Errorf("dial: %v", err)
			return
		}
		defer c.Close()
		reason, _ := Bridge(r.Context(), nil, c, ws, rec, Limits{Idle: time.Minute, AllowClipboard: false, tick: 50 * time.Millisecond})
		reasonCh <- reason
		_ = ws.Close(websocket.StatusNormalClosure, "")
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil) //nolint:bodyclose
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()

	send := func(raw string) {
		if err := ws.Write(ctx, websocket.MessageText, []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	read := func() string {
		_, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	send(Encode("key", "65", "1"))
	if got := read(); got != Encode("echo", "key", "65", "1") {
		t.Fatalf("relay: %q", got)
	}
	// Clipboard is blocked by policy in both directions: it never reaches guacd, so no echo.
	send(Encode("clipboard", "1", "text/plain"))
	send(Encode("mouse", "1", "2", "0"))
	if got := read(); got != Encode("echo", "mouse", "1", "2", "0") {
		t.Fatalf("clipboard should have been dropped, got %q", got)
	}
	// Browser disconnects.
	send(Encode("disconnect"))
	select {
	case r := <-reasonCh:
		if r != "user_exit" {
			t.Fatalf("reason %q", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bridge did not end")
	}
	if len(recorded) < 2 || !strings.HasPrefix(recorded[0], "4.echo") {
		t.Fatalf("recording captured %v", recorded)
	}
}

type recFunc func(string) error

func (f recFunc) Write(raw string) error { return f(raw) }
