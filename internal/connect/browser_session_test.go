// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/guac"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/target"
)

// stubBrowserDocker is a stand-in docker CLI for an application session:
// every call succeeds, `inspect` answers with a relay on both networks, and
// each call is appended to a log.
func stubBrowserDocker(t *testing.T) (docker, calls string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in docker CLI is a shell script")
	}
	dir := t.TempDir()
	calls = filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + calls + "'\n" +
		"if [ \"$1\" = inspect ]; then for a in \"$@\"; do n=$a; done; n=${n#zanskar-apprelay-}; printf 'bridge=127.0.0.1\\nzanskar-net-%s=172.30.0.2\\n' \"$n\"; fi\n" +
		"if [ \"$1\" = network ] && [ \"$2\" = inspect ]; then printf '172.30.0.0/16\\n'; fi\n" +
		"if [ \"$1\" = run ]; then echo \"ENV APP_URL=$APP_URL RESOLVER_RULES=$RESOLVER_RULES ZANSKAR_APPRELAY=$ZANSKAR_APPRELAY\" >> '" + calls + "'; fi\nexit 0\n"
	docker = filepath.Join(dir, "docker")
	if err := os.WriteFile(docker, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test stub
		t.Fatal(err)
	}
	return docker, calls
}

// appRig is the desktop rig with an application and a policy granting http.
func appRig(t *testing.T) (*desktopRig, string, string) {
	t.Helper()
	r := newDesktopRig(t)
	docker, calls := stubBrowserDocker(t)
	r.h.DockerPath = docker
	r.h.StateDir = t.TempDir()
	r.h.BrowserImage = func() string { return "ghcr.io/albatroxxx/zanskar-browser:test" }
	r.h.DBProxyImage = func() string { return "ghcr.io/albatroxxx/zanskar:test" }
	r.h.AppsMaxSessions = 1
	apps := &policy.Policy{Name: "apps", UserID: r.alice.ID, Enabled: true, IdleTimeoutMinutes: 15, AllowClipboard: true,
		Selector: policy.Selector{Tags: map[string]string{"app": "yes"}}, Protocols: []string{"http"}}
	if err := r.h.Policies.Create(r.ctx, apps); err != nil {
		t.Fatal(err)
	}
	tg := &target.Target{Name: "wiki", AppUpstream: "http://10.0.0.50:8080", Tags: map[string]string{"app": "yes"}}
	if err := r.h.Targets.Create(r.ctx, tg); err != nil {
		t.Fatal(err)
	}
	return r, tg.ID, calls
}

// TestApplicationSessionEndToEnd: an http ticket opens a recorded session
// drawn by guacd: the browser and its relay are started with the upstream's
// resolved address and the relay's address in the resolver rule, guacd is
// handed the relay's bridge address as a VNC server, the session row and
// audit carry protocol http, and disconnecting ends the session, finishes
// the recording and removes the containers.
func TestApplicationSessionEndToEnd(t *testing.T) {
	r, id, calls := appRig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ws, _, err := r.dial(ctx, r.ticket(t, id, "http")) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	var seen string
	for !strings.Contains(seen, "7.zanskar,") {
		_, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v (got %q)", err, seen)
		}
		seen += string(data)
	}
	if !strings.Contains(seen, "7.zanskar,4.file,1.0,9.clipboard,1.1;") {
		t.Fatalf("policy flags: %q", seen)
	}
	start := lastEvent(t, r.connectFixture, "session.start")
	var d map[string]any
	_ = json.Unmarshal(start.Details, &d)
	if d["protocol"] != "http" || d["target_id"] != id {
		t.Fatalf("session.start %v", d)
	}
	if live := r.h.Registry.List(); len(live) != 1 || live[0].Protocol != "http" || live[0].GuacID == "" {
		t.Fatalf("registry: %+v", live)
	}
	if err := ws.Write(ctx, websocket.MessageText, []byte(guac.Encode("disconnect"))); err != nil {
		t.Fatal(err)
	}
	ended := false
	for i := 0; i < 300 && !ended; i++ {
		s, err := r.h.Sessions.Get(r.ctx, start.ObjectID)
		ended = err == nil && s.EndedAt != nil
		if !ended {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !ended {
		t.Fatal("the application session never ended")
	}
	rec, err := r.h.Sessions.GetRecording(r.ctx, d["recording_id"].(string))
	if err != nil || rec.FinishedAt == nil || rec.Format != "guac" {
		t.Fatalf("recording %+v %v", rec, err)
	}
	// What the containers were told, and that they are gone.
	var log string
	for i := 0; i < 100; i++ {
		b, _ := os.ReadFile(calls) // #nosec G304 -- test temp dir
		log = string(b)
		if strings.Contains(log, "network rm zanskar-net-") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, want := range []string{
		"network create --internal", "run -d --rm --name zanskar-apprelay-" + start.ObjectID,
		`"to":"10.0.0.50:8080"`, "network connect bridge zanskar-apprelay-" + start.ObjectID,
		"run -d --rm --name zanskar-browser-" + start.ObjectID, "APP_URL=http://10.0.0.50:8080/", "RESOLVER_RULES=MAP 10.0.0.50 172.30.0.2, MAP * ~NOTFOUND",
		"rm -f zanskar-browser-" + start.ObjectID, "rm -f zanskar-apprelay-" + start.ObjectID, "network rm zanskar-net-" + start.ObjectID,
	} {
		if !strings.Contains(log, want) {
			t.Errorf("docker never saw %q:\n%s", want, log)
		}
	}
	if _, err := os.Stat(filepath.Join(r.h.StateDir, "browser-seccomp.json")); err != nil {
		t.Fatalf("seccomp profile not written: %v", err)
	}
}

// TestApplicationSessionCap: past ZANSKAR_APPS_MAX_SESSIONS the socket is
// refused with 503 too_many_sessions and no container is started; a
// terminal session does not count against it.
func TestApplicationSessionCap(t *testing.T) {
	r, id, calls := appRig(t)
	r.h.Registry.Add(context.Background(), gateway.Live{SessionID: "other-ssh", Protocol: "ssh"})
	r.h.Registry.Add(context.Background(), gateway.Live{SessionID: "other-app", Protocol: "http"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, resp, err := r.dial(ctx, r.ticket(t, id, "http"))
	if err == nil {
		ws.CloseNow()
		t.Fatal("a session past the cap opened")
	}
	if resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("got %v, want 503", resp)
	}
	_ = resp.Body.Close()
	if _, err := os.Stat(calls); err == nil {
		t.Fatal("a container was started for a refused session")
	}
	if ev := lastEvent(t, r.connectFixture, "session.connect"); !strings.Contains(string(ev.Details), "too_many_sessions") {
		t.Fatalf("refusal not audited: %s", ev.Details)
	}
}

// TestApplicationSessionRefusesForbiddenUpstream: an application whose
// upstream resolves to a forbidden address (the cloud metadata service) is
// refused before any container is made, and the refusal is audited.
func TestApplicationSessionRefusesForbiddenUpstream(t *testing.T) {
	r, _, calls := appRig(t)
	r.h.Prober = &target.Prober{}
	tg := &target.Target{Name: "meta", AppUpstream: "http://169.254.169.254", Tags: map[string]string{"app": "yes"}}
	if err := r.h.Targets.Create(r.ctx, tg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, resp, err := r.dial(ctx, r.ticket(t, tg.ID, "http"))
	if err == nil {
		ws.CloseNow()
		t.Fatal("a forbidden upstream opened")
	}
	if resp == nil || resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("got %v, want 422 address_forbidden", resp)
	}
	_ = resp.Body.Close()
	if _, err := os.Stat(calls); err == nil {
		t.Fatal("a container was started for a forbidden upstream")
	}
}
