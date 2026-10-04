// SPDX-License-Identifier: Apache-2.0

package dbgw

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/gateway/dbgw/dbtest"
	"github.com/albatroxxx/zanskar/internal/recording"
)

// TestBridgePostgresEndToEnd runs a real database session: a pgbouncer
// sidecar holds the credential, a psql container talks to it, and the
// browser side of the WebSocket runs a query and quits. The client container
// never carries the password, the session is recorded, and every Docker
// object the session made is gone afterwards.
func TestBridgePostgresEndToEnd(t *testing.T) {
	dbtest.RequireDocker(t)
	const password = "upstream-only-pw-7"
	host, port := dbtest.StartPostgres(t, password)
	sessionID := "t" + strconv.FormatInt(time.Now().UnixNano(), 36)
	spec := Spec{Engine: "postgres", Host: host, Port: port, Database: "app", Username: "postgres",
		Password: password, SessionID: sessionID, TLSMode: "disable"}
	network, proxy, client := names(sessionID)

	store := &recording.LocalStorage{Dir: t.TempDir()}
	type result struct {
		reason string
		err    error
	}
	done := make(chan result, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		rec, _, err := recording.NewAsciicast(r.Context(), store, sessionID+".cast", recording.Header{Width: 100, Height: 30})
		if err != nil {
			done <- result{"", err}
			return
		}
		reason, err := Bridge(r.Context(), nil, "docker", spec, ws, rec, 100, 30, Limits{Idle: time.Minute, SessionID: sessionID})
		_, _, _ = rec.Close()
		done <- result{reason, err}
		_ = ws.Close(websocket.StatusNormalClosure, reason)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	send := func(d string) {
		b, _ := json.Marshal(clientFrame{T: "i", D: d})
		if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
			t.Fatal(err)
		}
	}

	var output string
	asked, inspected := false, false
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			break
		}
		if typ == websocket.MessageText {
			continue // ready / end control frames
		}
		output += string(data)
		if !inspected && strings.Contains(output, "=#") {
			// While the session runs: the client container must not hold
			// the upstream password anywhere it could read it.
			cfg := dbtest.Docker(t, "inspect", client, "-f", "{{json .Config.Env}} {{json .Config.Cmd}} {{json .Args}}")
			if strings.Contains(cfg, password) {
				t.Fatalf("the client container carries the upstream password: %s", cfg)
			}
			inspected = true
		}
		if !asked && strings.Contains(output, "=#") {
			send("SELECT 41 + 1 AS answer;\r")
			asked = true
		}
		if asked && strings.Contains(output, " 42") {
			send("\\q\r")
		}
	}
	if !strings.Contains(output, " 42") {
		t.Fatalf("query output never arrived:\n%s", output)
	}
	res := <-done
	if res.err != nil || res.reason != "user_exit" {
		t.Fatalf("bridge ended %q: %v", res.reason, res.err)
	}

	raw, err := os.ReadFile(store.Dir + "/" + sessionID + ".cast")
	if err != nil || !strings.Contains(string(raw), "42") {
		t.Fatalf("recording does not hold the session: %v", err)
	}
	for _, obj := range [][]string{{"container", "inspect", proxy}, {"container", "inspect", client}, {"network", "inspect", network}} {
		if exec.Command("docker", obj...).Run() == nil { // #nosec G204 -- fixed test arguments
			t.Errorf("%s %s is still there after the session", obj[0], obj[2])
		}
	}
}
