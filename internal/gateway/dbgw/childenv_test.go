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
)

// callMark starts each docker call in the dump envDumpDocker writes.
const callMark = "@@docker@@ "

// envDumpDocker writes a stand-in docker CLI that appends its arguments and
// its whole environment to a file, then behaves as stubDockerScript does. The
// file's path is written into the script itself: a variable naming it would
// not reach the child, which is the point of the test.
func envDumpDocker(t *testing.T) (docker, dump string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in docker CLI is a shell script")
	}
	dir := t.TempDir()
	dump = filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\n{ echo \"" + callMark + "$*\"; env; } >> '" + dump + "'\n" +
		strings.TrimPrefix(stubDockerScript, "#!/bin/sh\n")
	docker = filepath.Join(dir, "docker")
	if err := os.WriteFile(docker, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return docker, dump
}

// dockerCalls splits the dump into one entry per docker call: its arguments
// and the environment it was started with.
func dockerCalls(t *testing.T, dump string) (calls []struct{ args, env string }) {
	t.Helper()
	raw, err := os.ReadFile(dump) // #nosec G304 -- the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range strings.Split(string(raw), callMark)[1:] {
		args, env, _ := strings.Cut(c, "\n")
		calls = append(calls, struct{ args, env string }{args, "\n" + env})
	}
	return calls
}

// TestDockerCommandEnv: a docker child's environment is the allow list's
// variables that are set, in its order, then the session's own; nothing else
// of the gateway's. With none of them set it is empty but not nil, since a nil
// Env would hand the child the gateway's whole environment.
func TestDockerCommandEnv(t *testing.T) {
	for _, k := range childEnvVars {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}
	t.Setenv("ZANSKAR_MASTER_KEY", "canary-master-key")
	cmd := dockerCommand(t.Context(), "docker", nil, "ps")
	if cmd.Env == nil || len(cmd.Env) != 0 {
		t.Fatalf("with nothing to pass, Env = %#v; want empty and not nil", cmd.Env)
	}

	t.Setenv("PATH", "/usr/bin:/bin")
	t.Setenv("HOME", "/var/lib/zanskar")
	t.Setenv("DOCKER_CONTEXT", "colima")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/990")
	cmd = dockerCommand(t.Context(), "docker", []string{"ZANSKAR_DBPROXY={}"}, "run")
	want := []string{"PATH=/usr/bin:/bin", "HOME=/var/lib/zanskar", "DOCKER_CONTEXT=colima", "XDG_RUNTIME_DIR=/run/user/990", "ZANSKAR_DBPROXY={}"}
	if strings.Join(cmd.Env, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Env = %q\nwant  %q", cmd.Env, want)
	}
}

// TestDockerChildrenGetNoGatewaySecrets: every docker command a database
// session runs (network, proxy, client, teardown) and the reaper's listings
// start with the variables docker needs and none of the gateway's own: not
// the master key, the database DSN or the webhook secret, nor a cloud
// credential the gateway happens to hold. The proxy still gets its own
// configuration, which it reads by name.
func TestDockerChildrenGetNoGatewaySecrets(t *testing.T) {
	docker, dump := envDumpDocker(t)
	secrets := map[string]string{
		"ZANSKAR_MASTER_KEY":          "canary-master-key",
		"ZANSKAR_DB_DSN":              "postgres://zanskar:canary-dsn-password@db.internal/zanskar",
		"ZANSKAR_SIEM_WEBHOOK_SECRET": "canary-webhook-secret",
		"AWS_SECRET_ACCESS_KEY":       "canary-aws-secret",
	}
	for k, v := range secrets {
		t.Setenv(k, v)
	}
	const dockerHost = "unix:///run/zanskar-test/docker.sock"
	t.Setenv("DOCKER_HOST", dockerHost)

	spec := Spec{Engine: "postgres", Host: "db.internal", Port: 5432, Database: "app", Username: "svc", Password: "upstream-pw", SessionID: "envcheck", TLSMode: "disable"}
	done := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			done <- err
			return
		}
		defer ws.CloseNow()
		_, err = Bridge(r.Context(), nil, docker, spec, ws, nil, 80, 24, Limits{SessionID: spec.SessionID, Idle: time.Minute})
		done <- err
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	// The client echoes a line once it runs; then the browser goes away and
	// the session is torn down.
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
	_ = ws.Close(websocket.StatusNormalClosure, "")
	if err := <-done; err != nil {
		t.Fatalf("bridge: %v", err)
	}
	if _, err := Reap(ctx, docker, nil); err != nil {
		t.Fatalf("reap: %v", err)
	}

	calls := dockerCalls(t, dump)
	// network create, proxy run, network connect, client run, the three
	// removals, and the reaper's two listings.
	if len(calls) != 9 {
		t.Fatalf("%d docker calls, want 9: %v", len(calls), calls)
	}
	proxyEnv := false
	for _, c := range calls {
		for k, v := range secrets {
			if strings.Contains(c.env, v) {
				t.Errorf("docker %.40s... was handed %s", c.args, k)
			}
		}
		if !strings.Contains(c.env, "\nDOCKER_HOST="+dockerHost+"\n") || !strings.Contains(c.env, "\nPATH=") {
			t.Errorf("docker %.40s... lacks DOCKER_HOST or PATH, which it needs to reach the daemon", c.args)
		}
		if strings.HasPrefix(c.args, "run -d") {
			proxyEnv = strings.Contains(c.env, "\nPGB_INI=") && strings.Contains(c.env, "upstream-pw")
		}
	}
	if !proxyEnv {
		t.Error("the proxy's docker run lacks PGB_INI, its configuration")
	}
}
