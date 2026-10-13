// SPDX-License-Identifier: Apache-2.0

package guac

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/gateway"
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
					if in.Opcode == "trigger-fs" {
						// Simulate guacd announcing the redirected drive.
						_, _ = c.Write([]byte(Encode("filesystem", "0", "Zanskar")))
						continue
					}
					if in.Opcode == "emit" {
						// Play the given wire-format instructions as guacd's output,
						// in one burst, before reading anything else.
						for _, raw := range in.Args {
							_, _ = c.Write([]byte(raw))
						}
						continue
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

// wantEnd is the end reason and message a session cancelled with cause
// must report.
func wantEnd(cause error) (reason, msg string) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)
	return gateway.CancelReason(ctx)
}

// TestBridgeRegistryEndReachesBrowser: a desktop the registry ends (an
// administrator, a restart, a policy change, the autoscaling sync) still
// tells the browser why, as an "error" instruction and then "disconnect",
// and the socket then closes normally, rather than vanishing under a
// cancelled read. Only a lost target carries status 519, which the console
// reads as "target lost" and, on an autoscaling group, answers with the
// failover dialog; an end the gateway decided carries 523, session closed.
func TestBridgeRegistryEndReachesBrowser(t *testing.T) {
	addr := fakeGuacd(t, nil)
	for _, cause := range []error{gateway.ErrAdminTerminated, gateway.ErrGatewayRestart, gateway.ErrPolicyRevoked, gateway.ErrTargetLost} {
		wantReason, wantMsg := wantEnd(cause)
		wantStatus := "523"
		if wantReason == "target_lost" {
			wantStatus = "519"
		}
		t.Run(wantReason, func(t *testing.T) {
			reg := gateway.NewRegistry()
			reasonCh := make(chan string, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
				if err != nil {
					return
				}
				defer ws.CloseNow()
				c, err := Dial(r.Context(), addr, Params{Protocol: "rdp", Args: map[string]string{}}, 2*time.Second)
				if err != nil {
					t.Errorf("dial: %v", err)
					return
				}
				defer c.Close()
				ctx := reg.Add(r.Context(), gateway.Live{SessionID: "s1", Protocol: "rdp"})
				defer reg.Remove("s1")
				reason, _ := Bridge(ctx, nil, c, ws, nil, Limits{Idle: time.Minute, tick: 20 * time.Millisecond})
				reasonCh <- reason
				// What the connect handler does once the session is recorded.
				_ = ws.Close(websocket.StatusNormalClosure, reason)
			}))
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil) //nolint:bodyclose
			if err != nil {
				t.Fatal(err)
			}
			defer ws.CloseNow()
			// next returns the next instruction other than the heartbeat.
			next := func() (Instruction, error) {
				for {
					_, data, err := ws.Read(ctx)
					if err != nil {
						return Instruction{}, err
					}
					if raw := string(data); Opcode(raw) != "nop" {
						return Parse(raw)
					}
				}
			}

			// A round trip through guacd: the bridge is relaying both ways.
			if err := ws.Write(ctx, websocket.MessageText, []byte(Encode("key", "65", "1"))); err != nil {
				t.Fatal(err)
			}
			if in, err := next(); err != nil || in.Opcode != "echo" {
				t.Fatalf("relay: %+v %v", in, err)
			}
			if !reg.TerminateWithCause("s1", cause) {
				t.Fatal("the session is not in the registry")
			}
			in, err := next()
			if err != nil {
				t.Fatalf("the socket went before the end message: %v", err)
			}
			if in.Opcode != "error" || len(in.Args) != 2 || in.Args[0] != wantMsg || in.Args[1] != wantStatus {
				t.Fatalf("end message %+v, want error %q with status %s", in, wantMsg, wantStatus)
			}
			if in, err := next(); err != nil || in.Opcode != "disconnect" {
				t.Fatalf("after the end message: %+v %v, want disconnect", in, err)
			}
			if _, err := next(); websocket.CloseStatus(err) != websocket.StatusNormalClosure {
				t.Fatalf("after disconnect: %v, want a normal close", err)
			}
			select {
			case r := <-reasonCh:
				if r != wantReason {
					t.Fatalf("bridge reason %q, want %q", r, wantReason)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("bridge did not end")
			}
		})
	}
}

// floodGuacd completes the handshake and then pours out display data without
// end, as a busy desktop does, until the connection goes. stalled is closed
// once a write has been held up: the bridge has stopped taking the data,
// because the browser has stopped taking it from the bridge.
func floodGuacd(t *testing.T) (addr string, stalled <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	held := make(chan struct{})
	var once sync.Once
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		rd := NewReader(c)
		if in, err := rd.Read(); err != nil || in.Opcode != "select" {
			return
		}
		_, _ = c.Write([]byte(Encode("args", "VERSION_1_5_0")))
		for {
			in, err := rd.Read()
			if err != nil {
				return
			}
			if in.Opcode == "connect" {
				break
			}
		}
		_, _ = c.Write([]byte(Encode("ready", "$conn-1")))
		blob := []byte(Encode("blob", "1", strings.Repeat("A", 16<<10)))
		for {
			watch := time.AfterFunc(200*time.Millisecond, func() { once.Do(func() { close(held) }) })
			_, err := c.Write(blob)
			watch.Stop()
			if err != nil {
				return
			}
		}
	}()
	return ln.Addr().String(), held
}

// TestBridgeRegistryEndWithStalledBrowser: a browser that has stopped reading
// while the desktop pours out updates cannot hold the session open once the
// registry ends it, and neither can a heartbeat stuck behind those updates.
// The session's cancellation no longer aborts writes to the browser, so the
// end messages may wait behind a stuck one only until their own deadline.
func TestBridgeRegistryEndWithStalledBrowser(t *testing.T) {
	addr, stalled := floodGuacd(t)
	reg := gateway.NewRegistry()
	reasonCh := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer ws.CloseNow()
		c, err := Dial(r.Context(), addr, Params{Protocol: "rdp", Args: map[string]string{}}, 2*time.Second)
		if err != nil {
			t.Errorf("dial: %v", err)
			return
		}
		defer c.Close()
		ctx := reg.Add(r.Context(), gateway.Live{SessionID: "s1", Protocol: "rdp"})
		defer reg.Remove("s1")
		reason, _ := Bridge(ctx, nil, c, ws, nil, Limits{Idle: time.Minute, tick: 20 * time.Millisecond})
		reasonCh <- reason
		_ = ws.Close(websocket.StatusNormalClosure, reason)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil) //nolint:bodyclose
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	for {
		_, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("waiting for the updates: %v", err)
		}
		if Opcode(string(data)) == "blob" {
			break
		}
	}
	// Stop reading, and wait until the updates back up to guacd: the bridge
	// is stuck writing to this browser.
	select {
	case <-stalled:
	case <-ctx.Done():
		t.Fatal("the updates never backed up")
	}
	start := time.Now()
	if !reg.TerminateWithCause("s1", gateway.ErrAdminTerminated) {
		t.Fatal("the session is not in the registry")
	}
	select {
	case r := <-reasonCh:
		if r != "admin_terminated" {
			t.Fatalf("bridge reason %q, want admin_terminated", r)
		}
		t.Logf("ended %v after the termination", time.Since(start).Round(time.Millisecond))
	case <-time.After(10 * time.Second):
		t.Fatal("a browser that stopped reading held the session open")
	}
}

// runBridge starts a bridge over a real websocket with the given limits and
// returns a connected client plus helpers.
func runBridge(t *testing.T, addr string, lim Limits) (send func(string), read func() string) {
	t.Helper()
	return runBridgeRecorded(t, addr, lim, nil)
}

// runBridgeRecorded is runBridge with a recorder attached to the bridge.
func runBridgeRecorded(t *testing.T, addr string, lim Limits, rec Recorder) (send func(string), read func() string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		c, err := Dial(r.Context(), addr, Params{Protocol: "rdp", Args: map[string]string{}}, 2*time.Second)
		if err != nil {
			t.Errorf("dial: %v", err)
			return
		}
		defer c.Close()
		_, _ = Bridge(r.Context(), nil, c, ws, rec, lim)
		_ = ws.Close(websocket.StatusNormalClosure, "")
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil) //nolint:bodyclose
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.CloseNow() })
	send = func(raw string) {
		if err := ws.Write(ctx, websocket.MessageText, []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	read = func() string {
		_, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	return send, read
}

func TestBridgeFileTransferPolicy(t *testing.T) {
	addr := fakeGuacd(t, nil)

	// Disallowed: "put" never reaches guacd (no echo) and the server's
	// "filesystem" announcement is dropped; the following mouse echo proves
	// the stream is still alive.
	send, read := runBridge(t, addr, Limits{Idle: time.Minute, AllowFileTransfer: false, tick: 50 * time.Millisecond})
	send(Encode("put", "0", "1", "application/octet-stream", "/x.txt"))
	send(Encode("trigger-fs"))
	send(Encode("mouse", "1", "1", "0"))
	if got := read(); got != Encode("echo", "mouse", "1", "1", "0") {
		t.Fatalf("expected put and filesystem to be dropped, got %q", got)
	}

	// Allowed: both pass.
	send, read = runBridge(t, addr, Limits{Idle: time.Minute, AllowFileTransfer: true, tick: 50 * time.Millisecond})
	send(Encode("put", "0", "1", "application/octet-stream", "/x.txt"))
	if got := read(); got != Encode("echo", "put", "0", "1", "application/octet-stream", "/x.txt") {
		t.Fatalf("put should pass when allowed, got %q", got)
	}
	send(Encode("trigger-fs"))
	if got := read(); got != Encode("filesystem", "0", "Zanskar") {
		t.Fatalf("filesystem should pass when allowed, got %q", got)
	}
}

// TestDialUnreachableIsSentinel: a guacd that does not answer at all is
// reported through ErrGuacdUnreachable, so the desktop handler can tell the
// user "the desktop service is down" rather than "could not connect to the
// target".
func TestDialUnreachableIsSentinel(t *testing.T) {
	// A closed loopback port: nothing listens, the dial is refused at once.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	_, err = Dial(context.Background(), addr, Params{Protocol: "rdp"}, 2*time.Second)
	if !errors.Is(err, ErrGuacdUnreachable) {
		t.Fatalf("want ErrGuacdUnreachable, got %v", err)
	}
	if !strings.Contains(err.Error(), addr) {
		t.Fatalf("the address tried should be in the error for the journal: %v", err)
	}
}

// A dropped stream is the whole stream. Guacamole opens a clipboard or file
// stream with one instruction and sends the content afterwards as blobs, so
// the bridge must drop the blobs and the end with the opening instruction,
// answer guacd on the browser's behalf so it frees the stream, and keep the
// rest of the session (here a "sync") flowing.
func TestBridgeClipboardStreamData(t *testing.T) {
	addr := fakeGuacd(t, nil)
	stream := []string{Encode("clipboard", "0", "text/plain"), Encode("blob", "0", "c2VjcmV0"), Encode("end", "0"), Encode("sync", "1")}
	refused := Encode("echo", "ack", "0", "blocked by policy", "771")

	var mu sync.Mutex
	var recorded []string
	rec := recFunc(func(raw string) error { mu.Lock(); recorded = append(recorded, raw); mu.Unlock(); return nil })
	send, read := runBridgeRecorded(t, addr, Limits{Idle: time.Minute, AllowClipboard: false, tick: 50 * time.Millisecond}, rec)
	send(Encode("emit", stream...))
	if got := read(); got != Encode("sync", "1") {
		t.Fatalf("clipboard off: the stream must not reach the browser, got %q", got)
	}
	if got := read(); got != refused {
		t.Fatalf("clipboard off: guacd must be told the stream was refused, got %q", got)
	}
	mu.Lock()
	for _, raw := range recorded {
		if op := Opcode(raw); op == "clipboard" || op == "blob" || op == "end" {
			t.Fatalf("a dropped frame must not be recorded: %q", raw)
		}
	}
	mu.Unlock()

	send, read = runBridge(t, addr, Limits{Idle: time.Minute, AllowClipboard: true, tick: 50 * time.Millisecond})
	send(Encode("emit", stream...))
	for _, want := range stream {
		if got := read(); got != want {
			t.Fatalf("clipboard on: want %q, got %q", want, got)
		}
	}
	// Nothing was refused, so nothing was acknowledged for guacd: the next
	// thing the browser hears is its own echo.
	send(Encode("mouse", "1", "1", "0"))
	if got := read(); got != Encode("echo", "mouse", "1", "1", "0") {
		t.Fatalf("clipboard on: unexpected %q", got)
	}
}

func TestBridgeFileStreamData(t *testing.T) {
	addr := fakeGuacd(t, nil)
	// A download ("file", stream 0), a directory listing ("body" names the
	// object first and the stream second: stream 3) and, in the same burst, a
	// display update on stream 2 which must arrive intact.
	download := []string{Encode("file", "0", "application/octet-stream", "secret.txt"), Encode("blob", "0", "c2VjcmV0"), Encode("end", "0")}
	listing := []string{Encode("body", "1", "3", "text/plain", "/"), Encode("blob", "3", "c2VjcmV0"), Encode("end", "3")}
	display := []string{Encode("img", "2", "14", "0", "image/png", "0", "0"), Encode("blob", "2", "iVBORw0KGgo="), Encode("end", "2")}
	var burst []string
	burst = append(burst, download...)
	burst = append(burst, listing...)
	burst = append(burst, display...)
	burst = append(burst, Encode("sync", "1"))

	send, read := runBridge(t, addr, Limits{Idle: time.Minute, AllowFileTransfer: false, tick: 50 * time.Millisecond})
	send(Encode("emit", burst...))
	for _, want := range append(append([]string{}, display...), Encode("sync", "1")) {
		if got := read(); got != want {
			t.Fatalf("files off: want %q, got %q", want, got)
		}
	}
	for _, idx := range []string{"0", "3"} {
		if want, got := Encode("echo", "ack", idx, "blocked by policy", "771"), read(); got != want {
			t.Fatalf("files off: want %q, got %q", want, got)
		}
	}

	send, read = runBridge(t, addr, Limits{Idle: time.Minute, AllowFileTransfer: true, tick: 50 * time.Millisecond})
	send(Encode("emit", burst...))
	for _, want := range burst {
		if got := read(); got != want {
			t.Fatalf("files on: want %q, got %q", want, got)
		}
	}
}

// guacd frees a refused stream without an "end" and reuses the index, often
// for the display. The next opening instruction on that index must clear the
// block, and a later refused stream on it must be blocked again.
func TestBridgeBlockedIndexReuse(t *testing.T) {
	addr := fakeGuacd(t, nil)
	display := []string{Encode("img", "7", "14", "0", "image/png", "0", "0"), Encode("blob", "7", "iVBORw0KGgo="), Encode("end", "7")}
	burst := []string{Encode("clipboard", "7", "text/plain"), Encode("blob", "7", "c2VjcmV0")}
	burst = append(burst, display...)
	burst = append(burst, Encode("clipboard", "7", "text/plain"), Encode("blob", "7", "c2VjcmV0"), Encode("end", "7"), Encode("sync", "2"))

	send, read := runBridge(t, addr, Limits{Idle: time.Minute, AllowClipboard: false, tick: 50 * time.Millisecond})
	send(Encode("emit", burst...))
	for _, want := range append(append([]string{}, display...), Encode("sync", "2")) {
		if got := read(); got != want {
			t.Fatalf("want %q, got %q", want, got)
		}
	}
}

// The browser's side of the same rule: the data of a stream the browser is
// not allowed to open never reaches guacd, however it is numbered.
func TestBridgeClientStreamData(t *testing.T) {
	addr := fakeGuacd(t, nil)
	mouse, echo := Encode("mouse", "1", "1", "0"), Encode("echo", "mouse", "1", "1", "0")

	send, read := runBridge(t, addr, Limits{Idle: time.Minute, AllowClipboard: false, AllowFileTransfer: false, tick: 50 * time.Millisecond})
	for _, raw := range []string{
		Encode("clipboard", "0", "text/plain"), Encode("blob", "0", "c2VjcmV0"), Encode("end", "0"),
		// An upload: "put" names the object first and the stream second.
		Encode("put", "0", "1", "application/octet-stream", "/x.txt"), Encode("blob", "1", "c2VjcmV0"), Encode("end", "1"),
		// Index spellings guacd's atoi would map onto a stream the bridge
		// never saw opened are refused outright.
		Encode("blob", "01", "c2VjcmV0"), Encode("blob", "+1", "c2VjcmV0"), Encode("end", "1 "),
		mouse,
	} {
		send(raw)
	}
	if got := read(); got != echo {
		t.Fatalf("blocked stream data reached guacd: %q", got)
	}
	// A microphone stream reusing index 0 is allowed, and so is its data.
	send(Encode("audio", "0", "audio/L16;rate=44100,channels=2"))
	send(Encode("blob", "0", "AAAA"))
	if got := read(); got != Encode("echo", "audio", "0", "audio/L16;rate=44100,channels=2") {
		t.Fatalf("allowed stream on a reused index: %q", got)
	}
	if got := read(); got != Encode("echo", "blob", "0", "AAAA") {
		t.Fatalf("allowed stream's data on a reused index: %q", got)
	}

	send, read = runBridge(t, addr, Limits{Idle: time.Minute, AllowClipboard: true, AllowFileTransfer: true, tick: 50 * time.Millisecond})
	for _, raw := range []string{
		Encode("clipboard", "0", "text/plain"), Encode("blob", "0", "c2VjcmV0"), Encode("end", "0"),
		Encode("put", "0", "1", "application/octet-stream", "/x.txt"), Encode("blob", "1", "c2VjcmV0"), Encode("end", "1"),
	} {
		send(raw)
		if want, got := Encode("echo", append([]string{Opcode(raw)}, mustParse(t, raw).Args...)...), read(); got != want {
			t.Fatalf("allowed: want %q, got %q", want, got)
		}
	}
}

func mustParse(t *testing.T, raw string) Instruction {
	t.Helper()
	in, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func TestStreamIndex(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		arg  int
		want int
		ok   bool
	}{
		{Encode("blob", "0", "c2VjcmV0"), 0, 0, true},
		{Encode("end", "5"), 0, 5, true},
		{Encode("body", "1", "3", "text/plain", "/"), 1, 3, true},
		{Encode("put", "0", "12", "application/octet-stream", "/x"), 1, 12, true},
		{Encode("file", "63", "text/plain", "日本語.txt"), 0, 63, true},
		{Encode("blob", "00", "x"), 0, 0, false},
		{Encode("blob", "+1", "x"), 0, 0, false},
		{Encode("blob", "1 ", "x"), 0, 0, false},
		{Encode("blob", "-1", "x"), 0, 0, false},
		{Encode("blob", "1024", "x"), 0, 0, false},
		{Encode("blob", "", "x"), 0, 0, false},
		{Encode("blob"), 0, 0, false},
		{Encode("body", "1"), 1, 0, false},
		{"4.blob,1.0", 0, 0, false},             // unterminated
		{"4.blob,9.0;", 0, 0, false},            // length overruns the instruction
		{"4.blob,1.0x8.c2VjcmV0;", 0, 0, false}, // bad separator
		{"", 0, 0, false},
	} {
		got, ok := streamIndex(tc.raw, tc.arg)
		if ok != tc.ok || got != tc.want {
			t.Errorf("streamIndex(%q, %d) = %d, %v; want %d, %v", tc.raw, tc.arg, got, ok, tc.want, tc.ok)
		}
	}
}
