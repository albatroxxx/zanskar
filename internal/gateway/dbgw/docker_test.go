// SPDX-License-Identifier: Apache-2.0

package dbgw

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
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

// bridgeSession runs one PostgreSQL session through Bridge against a real
// upstream, calls probe while the client sits at its prompt, then runs a
// query through the proxy and quits. It returns what the browser saw, the
// end reason and the bridge's error.
func bridgeSession(t *testing.T, spec Spec, probe func()) (output, reason string, err error) {
	t.Helper()
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
		rec, _, err := recording.NewAsciicast(r.Context(), store, spec.SessionID+".cast", recording.Header{Width: 100, Height: 30})
		if err != nil {
			done <- result{"", err}
			return
		}
		reason, err := Bridge(r.Context(), nil, "docker", spec, ws, rec, 100, 30, Limits{Idle: time.Minute, SessionID: spec.SessionID})
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
	asked, quit := false, false
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			break
		}
		if typ == websocket.MessageText {
			continue // ready / end control frames
		}
		output += string(data)
		switch {
		case !asked && strings.Contains(output, "=#"):
			probe()
			send("SELECT 41 + 1 AS answer;\r")
			asked = true
		case asked && !quit && strings.Contains(output, " 42"):
			send("\\q\r")
			quit = true
		}
	}
	res := <-done
	return output, res.reason, res.err
}

// TestBridgeClientHasNoEgress: the session network is internal, so the
// client container reaches nothing but its proxy: not the database (the
// address the proxy dials, tried from inside the client, has no route) and
// not an outside address. The proxy, alone also on the runtime's default
// bridge, reaches the upstream: the query goes through it. Every object the
// session made carries its labels.
func TestBridgeClientHasNoEgress(t *testing.T) {
	dbtest.RequireDocker(t)
	const password = "upstream-only-pw-8"
	host, port := dbtest.StartPostgres(t, password)
	sessionID := "e" + strconv.FormatInt(time.Now().UnixNano(), 36)
	spec := Spec{Engine: "postgres", Host: host, Port: port, Database: "app", Username: "postgres",
		Password: password, SessionID: sessionID, TLSMode: "disable"}
	network, proxy, client := names(sessionID)
	const networksOf = `{{range $n, $_ := .NetworkSettings.Networks}}{{$n}} {{end}}`

	output, reason, err := bridgeSession(t, spec, func() {
		if got := strings.TrimSpace(dbtest.Docker(t, "inspect", client, "-f", networksOf)); got != network {
			t.Errorf("client networks %q, want only %q", got, network)
		}
		if got := strings.Fields(dbtest.Docker(t, "inspect", proxy, "-f", networksOf)); !slices.Contains(got, network) || !slices.Contains(got, "bridge") {
			t.Errorf("proxy networks %q, want %q and bridge", got, network)
		}
		if got := dbtest.Docker(t, "network", "inspect", network, "-f", "{{.Internal}}"); got != "true" {
			t.Errorf("session network internal=%s", got)
		}
		t.Logf("session network gateway: %q (no address, which the template prints as invalid IP, means the isolated gateway mode took)",
			dbtest.Docker(t, "network", "inspect", network, "-f", "{{(index .IPAM.Config 0).Gateway}}"))
		for _, obj := range [][]string{
			{"inspect", client, "-f", `{{index .Config.Labels "zanskar.session"}}`},
			{"inspect", proxy, "-f", `{{index .Config.Labels "zanskar.session"}}`},
			{"network", "inspect", network, "-f", `{{index .Labels "zanskar.session"}}`},
		} {
			if got := dbtest.Docker(t, obj...); got != sessionID {
				t.Errorf("%v: label %q, want %q", obj[:2], got, sessionID)
			}
		}
		// The upstream, exactly as the proxy reaches it, from inside the client.
		conn := "host=" + host + " port=" + strconv.Itoa(port) + " user=postgres dbname=app connect_timeout=3"
		out, err := exec.Command("docker", "exec", "-e", "PGPASSWORD="+password, client, "psql", conn, "-c", "select 1").CombinedOutput() // #nosec G204 -- fixed test arguments
		if err == nil {
			t.Errorf("the client container reached the upstream database directly:\n%s", out)
		}
		t.Logf("client to the upstream: %s", strings.TrimSpace(string(out)))
		if out, err := exec.Command("docker", "exec", client, "nc", "-z", "-w", "3", "1.1.1.1", "53").CombinedOutput(); err == nil { // #nosec G204 -- fixed test arguments
			t.Errorf("the client container reached an outside address:\n%s", out)
		}
	})
	if err != nil || reason != "user_exit" || !strings.Contains(output, " 42") {
		t.Fatalf("the session through the proxy ended %q, %v:\n%s", reason, err, output)
	}
}

// TestReapRemovesLeftoversByLabel: a labelled network and container that no
// session owns (what a crashed gateway leaves) are removed once they are old
// enough; a session the registry still runs, and anything younger than the
// age guard, is left alone.
func TestReapRemovesLeftoversByLabel(t *testing.T) {
	dbtest.RequireDocker(t)
	ghost := "ghost" + strconv.FormatInt(time.Now().UnixNano(), 36)
	network, proxy, _ := names(ghost)
	dbtest.Docker(t, networkArgs(ghost, network, false)...)
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", network).Run() }) // #nosec G204 -- fixed test arguments
	dbtest.Docker(t, append(append([]string{"run", "-d", "--rm", "--name", proxy, "--network", network}, labels(ghost)...), "postgres:16-alpine", "sleep", "300")...)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", proxy).Run() })                   // #nosec G204 -- fixed test arguments
	exists := func(args ...string) bool { return exec.Command("docker", args...).Run() == nil } // #nosec G204 -- fixed test arguments
	// Every other session on this daemon counts as live, so a test running
	// beside this one is never touched.
	dead := func(id string) bool { return id != ghost }

	if n, err := Reap(t.Context(), "docker", dead); err != nil || n != 0 {
		t.Fatalf("a start still in flight was reaped: %d %v", n, err)
	}
	run := func(ctx context.Context, args ...string) (string, error) {
		return dockerOutput(ctx, "docker", nil, args...)
	}
	later := time.Now().Add(reapMinAge + time.Minute)
	if n, err := reap(t.Context(), run, func(string) bool { return true }, later); err != nil || n != 0 {
		t.Fatalf("a live session's objects were reaped: %d %v", n, err)
	}
	if !exists("container", "inspect", proxy) || !exists("network", "inspect", network) {
		t.Fatal("the objects vanished while protected")
	}
	if n, err := reap(t.Context(), run, dead, later); err != nil || n != 2 {
		t.Fatalf("reap removed %d, %v", n, err)
	}
	if exists("container", "inspect", proxy) || exists("network", "inspect", network) {
		t.Fatal("the leftovers are still there")
	}
}
