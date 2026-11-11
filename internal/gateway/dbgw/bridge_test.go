// SPDX-License-Identifier: Apache-2.0

package dbgw

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/gateway"
)

// stubDockerScript stands in for the docker CLI: every set-up and teardown
// command succeeds, and the interactive client container (the "run" with
// -i) is cat, so whatever the browser types comes back.
const stubDockerScript = `#!/bin/sh
if [ "$1" = run ]; then
	for a in "$@"; do
		if [ "$a" = -i ]; then
			exec cat
		fi
	done
fi
exit 0
`

// stubDocker writes the stand-in CLI and returns its path.
func stubDocker(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in docker CLI is a shell script")
	}
	path := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(path, []byte(stubDockerScript), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// wantEnd is the end reason and message a session cancelled with cause
// must report.
func wantEnd(cause error) (reason, msg string) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)
	return gateway.CancelReason(ctx)
}

// TestBridgeOutputReachesTap: what the client prints goes to the session's
// tap as well as the browser, so an admin can watch it live (2026-11-11:
// the bridge wrote only to the recording and the browser).
func TestBridgeOutputReachesTap(t *testing.T) {
	docker := stubDocker(t)
	spec := Spec{Engine: "postgres", Host: "db.internal", Port: 5432, Database: "app", Username: "svc", Password: "x", SessionID: "s1", TLSMode: "disable"}
	reg := gateway.NewRegistry()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer ws.CloseNow()
		ctx := reg.Add(r.Context(), gateway.Live{SessionID: spec.SessionID, Protocol: "database"})
		defer reg.Remove(spec.SessionID)
		_, _ = Bridge(ctx, nil, docker, spec, ws, nil, 80, 24, Limits{SessionID: spec.SessionID, Idle: time.Minute, Tap: reg.Tap(spec.SessionID), tick: 20 * time.Millisecond})
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	b, _ := json.Marshal(clientFrame{T: "i", D: "ping\r"})
	if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
	var screen string
	for strings.Count(screen, "ping") < 2 {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("waiting for the echo: %v (screen %q)", err, screen)
		}
		if typ == websocket.MessageBinary {
			screen += string(data)
		}
	}
	tap := reg.Tap(spec.SessionID)
	if tap == nil {
		t.Fatal("the session is not in the registry")
	}
	_, replay, unsub := tap.Subscribe()
	defer unsub()
	if string(replay) != screen {
		t.Fatalf("tap holds %q, the browser saw %q", replay, screen)
	}
}

// TestBridgeRegistryEndReachesBrowser: a database session the registry ends
// (an administrator, a restart, a policy change) still tells the browser why
// in the end frame, and the socket then closes normally, rather than
// vanishing under a cancelled read. The client container runs under the
// session's context, so the cancellation kills it too; the end is still the
// registry's, not the client's exit.
func TestBridgeRegistryEndReachesBrowser(t *testing.T) {
	docker := stubDocker(t)
	spec := Spec{Engine: "postgres", Host: "db.internal", Port: 5432, Database: "app", Username: "svc", Password: "x", SessionID: "s1", TLSMode: "disable"}
	for _, cause := range []error{gateway.ErrAdminTerminated, gateway.ErrGatewayRestart, gateway.ErrPolicyRevoked, gateway.ErrTargetLost} {
		wantReason, wantMsg := wantEnd(cause)
		t.Run(wantReason, func(t *testing.T) {
			reg := gateway.NewRegistry()
			reasonCh := make(chan string, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
				if err != nil {
					return
				}
				defer ws.CloseNow()
				ctx := reg.Add(r.Context(), gateway.Live{SessionID: spec.SessionID, Protocol: "database"})
				defer reg.Remove(spec.SessionID)
				reason, err := Bridge(ctx, nil, docker, spec, ws, nil, 80, 24, Limits{SessionID: spec.SessionID, Idle: time.Minute, tick: 20 * time.Millisecond})
				if err != nil {
					t.Errorf("bridge: %v", err)
				}
				reasonCh <- reason
				// What the connect handler does once the session is recorded.
				_ = ws.Close(websocket.StatusNormalClosure, reason)
			}))
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil) //nolint:bodyclose // the library closes the handshake body
			if err != nil {
				t.Fatal(err)
			}
			defer ws.CloseNow()

			// The terminal echoes the line and the client prints it back: the
			// client is running and the bridge is reading the browser.
			b, _ := json.Marshal(clientFrame{T: "i", D: "ping\r"})
			if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
				t.Fatal(err)
			}
			var screen string
			for strings.Count(screen, "ping") < 2 {
				typ, data, err := ws.Read(ctx)
				if err != nil {
					t.Fatalf("waiting for the echo: %v (screen %q)", err, screen)
				}
				if typ == websocket.MessageBinary {
					screen += string(data)
				} else if strings.Contains(string(data), `"end"`) {
					t.Fatalf("ended before it was ended: %s (screen %q)", data, screen)
				}
			}
			if !reg.TerminateWithCause(spec.SessionID, cause) {
				t.Fatal("the session is not in the registry")
			}

			var end control
			for end.T != "end" {
				typ, data, err := ws.Read(ctx)
				if err != nil {
					t.Fatalf("the socket went before the end frame: %v", err)
				}
				if typ == websocket.MessageText {
					end = control{}
					_ = json.Unmarshal(data, &end)
				}
			}
			if end.Reason != wantReason || end.Msg != wantMsg {
				t.Fatalf("end frame %+v, want reason %q and msg %q", end, wantReason, wantMsg)
			}
			for {
				_, _, err := ws.Read(ctx)
				if err == nil {
					continue
				}
				if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
					t.Fatalf("after the end frame: %v, want a normal close", err)
				}
				break
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
