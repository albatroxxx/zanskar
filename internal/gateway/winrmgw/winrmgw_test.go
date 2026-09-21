// SPDX-License-Identifier: Apache-2.0

package winrmgw

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fakeShell upper-cases each line into stdout and returns exit code 0. It
// records whether Close was called so the test can assert cleanup.
type fakeShell struct {
	mu     sync.Mutex
	closed bool
	runErr error
}

func (f *fakeShell) Run(_ context.Context, line string, stdout, _ io.Writer) (int, error) {
	if f.runErr != nil {
		return 1, f.runErr
	}
	_, _ = io.WriteString(stdout, strings.ToUpper(line))
	return 0, nil
}

func (f *fakeShell) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

func (f *fakeShell) wasClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// serve runs Bridge behind a websocket endpoint and reports the end reason.
func serve(t *testing.T, sh Shell, lim Limits) (*httptest.Server, chan string) {
	t.Helper()
	reasonCh := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		reason, berr := Bridge(r.Context(), nil, sh, ws, nil, 80, 24, lim)
		if berr != nil {
			t.Errorf("bridge error: %v", berr)
		}
		reasonCh <- reason
		_ = ws.Close(websocket.StatusNormalClosure, "")
	}))
	t.Cleanup(srv.Close)
	return srv, reasonCh
}

func dial(t *testing.T, srv *httptest.Server) (*websocket.Conn, context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil) //nolint:bodyclose // library closes the handshake body
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return ws, ctx, cancel
}

func readReady(t *testing.T, ctx context.Context, ws *websocket.Conn) {
	t.Helper()
	typ, data, err := ws.Read(ctx)
	if err != nil || typ != websocket.MessageText || !strings.Contains(string(data), `"ready"`) {
		t.Fatalf("expected ready, got typ=%v data=%s err=%v", typ, data, err)
	}
}

// readUntil accumulates binary output until want appears, failing on an
// unexpected end control frame.
func readUntil(t *testing.T, ctx context.Context, ws *websocket.Conn, want string) string {
	t.Helper()
	var acc strings.Builder
	for !strings.Contains(acc.String(), want) {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("read waiting for %q: %v (got %q)", want, err, acc.String())
		}
		if typ == websocket.MessageBinary {
			acc.Write(data)
			continue
		}
		if strings.Contains(string(data), `"end"`) {
			t.Fatalf("unexpected end while waiting for %q: %s (got %q)", want, data, acc.String())
		}
	}
	return acc.String()
}

func readEnd(t *testing.T, ctx context.Context, ws *websocket.Conn) string {
	t.Helper()
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("waiting for end frame: %v", err)
		}
		if typ == websocket.MessageText && strings.Contains(string(data), `"end"`) {
			return string(data)
		}
	}
}

func sendText(t *testing.T, ctx context.Context, ws *websocket.Conn, s string) {
	t.Helper()
	if err := ws.Write(ctx, websocket.MessageText, []byte(s)); err != nil {
		t.Fatal(err)
	}
}

func TestBridgeReadyEchoAndRun(t *testing.T) {
	sh := &fakeShell{}
	srv, reasonCh := serve(t, sh, Limits{Idle: time.Minute, tick: 50 * time.Millisecond})
	ws, ctx, cancel := dial(t, srv)
	defer cancel()
	defer ws.CloseNow()

	readReady(t, ctx, ws)
	readUntil(t, ctx, ws, "PS> ") // initial prompt

	// Type a line; expect the echo ("hello") and the upper-cased output.
	sendText(t, ctx, ws, `{"t":"i","d":"hello\r"}`)
	got := readUntil(t, ctx, ws, "HELLO")
	if !strings.Contains(got, "hello") {
		t.Fatalf("expected local echo of 'hello', got %q", got)
	}

	// Exit ends the session cleanly.
	sendText(t, ctx, ws, `{"t":"i","d":"exit\r"}`)
	if end := readEnd(t, ctx, ws); !strings.Contains(end, "user_exit") {
		t.Fatalf("end frame: %s", end)
	}
	select {
	case r := <-reasonCh:
		if r != "user_exit" {
			t.Fatalf("reason %q", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bridge did not end")
	}
	if !sh.wasClosed() {
		t.Fatal("shell was not closed")
	}
}

func TestBridgeBackspaceEditing(t *testing.T) {
	sh := &fakeShell{}
	srv, _ := serve(t, sh, Limits{Idle: time.Minute, tick: 50 * time.Millisecond})
	ws, ctx, cancel := dial(t, srv)
	defer cancel()
	defer ws.CloseNow()
	readReady(t, ctx, ws)
	readUntil(t, ctx, ws, "PS> ")
	// "hX", then a DEL (JSON ) to erase the X, then "i\r" -> "hi" -> "HI".
	sendText(t, ctx, ws, `{"t":"i","d":"hX"}`)
	sendText(t, ctx, ws, "{\"t\":\"i\",\"d\":\"\x7f\"}")
	sendText(t, ctx, ws, `{"t":"i","d":"i\r"}`)
	if got := readUntil(t, ctx, ws, "HI"); !strings.Contains(got, "\b \b") {
		t.Fatalf("expected backspace erase sequence, got %q", got)
	}
}

func TestBridgeIdleTimeout(t *testing.T) {
	sh := &fakeShell{}
	srv, reasonCh := serve(t, sh, Limits{Idle: 150 * time.Millisecond, tick: 30 * time.Millisecond})
	ws, ctx, cancel := dial(t, srv)
	defer cancel()
	defer ws.CloseNow()
	readReady(t, ctx, ws)
	if end := readEnd(t, ctx, ws); !strings.Contains(end, "idle_timeout") {
		t.Fatalf("expected idle_timeout, got %s", end)
	}
	select {
	case r := <-reasonCh:
		if r != "idle_timeout" {
			t.Fatalf("reason %q", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bridge did not end")
	}
}

func TestBridgeBrowserClose(t *testing.T) {
	sh := &fakeShell{}
	srv, reasonCh := serve(t, sh, Limits{Idle: time.Minute, tick: 50 * time.Millisecond})
	ws, ctx, cancel := dial(t, srv)
	defer cancel()
	readReady(t, ctx, ws)
	readUntil(t, ctx, ws, "PS> ")
	_ = ws.Close(websocket.StatusNormalClosure, "bye")
	select {
	case r := <-reasonCh:
		if r != "user_exit" {
			t.Fatalf("reason on browser close %q", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bridge did not end on browser close")
	}
	if !sh.wasClosed() {
		t.Fatal("shell was not closed on browser close")
	}
}

func TestBridgeTargetLost(t *testing.T) {
	sh := &fakeShell{runErr: io.ErrUnexpectedEOF}
	srv, reasonCh := serve(t, sh, Limits{Idle: time.Minute, tick: 50 * time.Millisecond})
	ws, ctx, cancel := dial(t, srv)
	defer cancel()
	defer ws.CloseNow()
	readReady(t, ctx, ws)
	readUntil(t, ctx, ws, "PS> ")
	sendText(t, ctx, ws, `{"t":"i","d":"anything\r"}`)
	if end := readEnd(t, ctx, ws); !strings.Contains(end, "target_lost") {
		t.Fatalf("expected target_lost, got %s", end)
	}
	select {
	case r := <-reasonCh:
		if r != "target_lost" {
			t.Fatalf("reason %q", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bridge did not end")
	}
}
