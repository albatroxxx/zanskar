// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/dbgw/dbtest"
	"github.com/albatroxxx/zanskar/internal/gateway/guac"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/target"
)

// guacdImage is the guacd the install guide starts, by digest.
const guacdImage = "guacamole/guacd:1.6.0@sha256:8974eaa9ba32f713daf311e7cc8cd7e4cdfba1edea39eed75524e78ef4b08f4f"

// buildGatewayImage builds the gateway's release image for this machine's
// architecture from a fresh binary, for the relay beside the browser, and
// returns its tag. The build takes the release Dockerfile as it is.
func buildGatewayImage(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join("..", "..")
	bin := filepath.Join(dir, "zanskar")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "./cmd/zanskar") // #nosec G204 -- fixed test arguments
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the gateway for linux: %v\n%s", err, out)
	}
	if err := os.MkdirAll(filepath.Join(dir, "deploy", "docker", "data"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deploy", "docker", "data", ".keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	df, err := os.ReadFile(filepath.Join(root, "deploy", "Dockerfile.release"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), df, 0o600); err != nil {
		t.Fatal(err)
	}
	tag := "zanskar-gateway-test:" + strconv.FormatInt(time.Now().UnixNano(), 36)
	dbtest.Docker(t, "build", "-q", "-t", tag, dir)
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", tag).Run() }) // #nosec G204 -- fixed test arguments
	return tag
}

// container starts an image on the default bridge and returns its address
// there; it is removed with the test.
func container(t *testing.T, name string, args ...string) string {
	t.Helper()
	name += "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	dbtest.Docker(t, append([]string{"run", "-d", "--rm", "--name", name}, args...)...)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() }) // #nosec G204 -- fixed test arguments
	return dbtest.Docker(t, "inspect", "-f", "{{.NetworkSettings.Networks.bridge.IPAddress}}", name)
}

// TestApplicationSessionThroughRealBrowser: with a real guacd, the browser
// image and an nginx as the application, an http ticket ends in pixels:
// guacd draws the browser's screen into the session's socket, the
// containers sit on the networks the design says (the browser on the
// internal network alone, the relay on it and the bridge), and the end of
// the session removes all three. Needs ZANSKAR_TEST_DOCKER=1 and
// ZANSKAR_TEST_BROWSER_IMAGE naming a built browser image.
func TestApplicationSessionThroughRealBrowser(t *testing.T) {
	dbtest.RequireDocker(t)
	browserImage := os.Getenv("ZANSKAR_TEST_BROWSER_IMAGE")
	if browserImage == "" {
		t.Skip("set ZANSKAR_TEST_BROWSER_IMAGE to a built deploy/browser image")
	}
	relayImage := buildGatewayImage(t)
	upstreamIP := container(t, "zanskar-test-nginx", "nginx:alpine")
	// guacd on the default bridge, as the install guide starts it, published
	// on a loopback port the gateway (this process) dials. A developer whose
	// daemon runs in a VM that does not forward published ports (Colima)
	// starts guacd and a tunnel by hand and names it in
	// ZANSKAR_TEST_GUACD_ADDR.
	guacdAddr := os.Getenv("ZANSKAR_TEST_GUACD_ADDR")
	if guacdAddr == "" {
		guacdName := "zanskar-test-guacd-" + strconv.FormatInt(time.Now().UnixNano(), 36)
		dbtest.Docker(t, "run", "-d", "--rm", "--name", guacdName, "-p", "127.0.0.1:0:4822", "-e", "HOME=/tmp", "--read-only", "--tmpfs", "/tmp:size=256m,mode=1777", guacdImage)
		t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", guacdName).Run() }) // #nosec G204 -- fixed test arguments
		guacdPort := dbtest.Docker(t, "inspect", "-f", `{{(index (index .NetworkSettings.Ports "4822/tcp") 0).HostPort}}`, guacdName)
		guacdAddr = net.JoinHostPort("127.0.0.1", guacdPort)
	}

	f := newConnectFixture(t)
	// The gateway's own log, so a container that fails to start says why
	// in the test output.
	f.h.Log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	f.h.GuacdAddr = func() string { return guacdAddr }
	f.h.Storage = &recording.LocalStorage{Dir: t.TempDir()}
	f.h.Registry = gateway.NewRegistry()
	f.h.Prober = &target.Prober{}
	f.h.DialTimeout = 20 * time.Second
	f.h.DockerPath = "docker"
	f.h.StateDir = t.TempDir()
	f.h.BrowserImage = func() string { return browserImage }
	f.h.DBProxyImage = func() string { return relayImage }
	apps := &policy.Policy{Name: "apps", UserID: f.alice.ID, Enabled: true, IdleTimeoutMinutes: 15, AllowClipboard: true,
		Selector: policy.Selector{Tags: map[string]string{"app": "yes"}}, Protocols: []string{"http"}}
	if err := f.h.Policies.Create(f.ctx, apps); err != nil {
		t.Fatal(err)
	}
	tg := &target.Target{Name: "nginx", AppUpstream: "http://" + upstreamIP, Tags: map[string]string{"app": "yes"}}
	if err := f.h.Targets.Create(f.ctx, tg); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(f.srv)
	t.Cleanup(srv.Close)
	code, out := f.postConnect(t, srv.URL, tg.ID, "http")
	tok, _ := out["ticket"].(string)
	if code != http.StatusOK || tok == "" || out["ws_path"] != "/ws/desktop" {
		t.Fatalf("connect: %d %v", code, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws/desktop?width=1024&height=768&ticket="+tok, f.wsOptions("guacamole")) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()

	// Pixels: guacd sends image instructions (png, jpeg or webp blobs, or
	// img streams) once the browser has drawn something.
	drawn := regexp.MustCompile(`\d+\.(png|jpeg|webp|img|blob|size),`)
	var seen strings.Builder
	var sessionID string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		_, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v (seen %d bytes: %.300s)", err, seen.Len(), seen.String())
		}
		seen.Write(data)
		if sessionID == "" {
			if i := strings.Index(seen.String(), "7.zanskar,"); i > 0 {
				// The tunnel id instruction precedes the flags: "0.,<n>.<id>;"
				head := seen.String()[:i]
				if j := strings.LastIndex(head, "."); j > 0 {
					sessionID = strings.TrimSuffix(head[j+1:], ";")
				}
			}
		}
		if drawn.MatchString(seen.String()) && strings.Contains(seen.String(), "sync") {
			break
		}
	}
	if !drawn.MatchString(seen.String()) {
		t.Fatalf("no image instruction from guacd in 90 s: %.500s", seen.String())
	}
	if sessionID == "" {
		t.Fatalf("no session id before the flags: %.300s", seen.String())
	}
	netName, relayName, browserName := "zanskar-net-"+sessionID, "zanskar-apprelay-"+sessionID, "zanskar-browser-"+sessionID
	if internal := dbtest.Docker(t, "network", "inspect", "-f", "{{.Internal}}", netName); internal != "true" {
		t.Fatalf("the session network is not internal: %s", internal)
	}
	browserNets := dbtest.Docker(t, "inspect", "-f", `{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}`, browserName)
	if strings.TrimSpace(browserNets) != netName {
		t.Fatalf("the browser is on %q, want only %s", browserNets, netName)
	}
	relayNets := dbtest.Docker(t, "inspect", "-f", `{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}`, relayName)
	if !strings.Contains(relayNets, netName) || !strings.Contains(relayNets, "bridge") {
		t.Fatalf("the relay is on %q, want %s and bridge", relayNets, netName)
	}
	for _, name := range []string{browserName, relayName} {
		for _, want := range []string{`"ReadonlyRootfs":true`, `"CapDrop":["ALL"]`, `"no-new-privileges"`} {
			if got := dbtest.Docker(t, "inspect", "-f", "{{json .HostConfig}}", name); !strings.Contains(got, want) {
				t.Errorf("%s host config lacks %s", name, want)
			}
		}
	}
	if got := dbtest.Docker(t, "inspect", "-f", "{{json .HostConfig.SecurityOpt}}", browserName); !strings.Contains(got, "seccomp=") {
		t.Errorf("the browser runs without the seccomp profile: %s", got)
	}
	// The request reached nginx through the relay: its log has the GET.
	if logs := dbtest.Docker(t, "logs", strings.TrimSpace(dbtest.Docker(t, "ps", "-q", "--filter", "ancestor=nginx:alpine"))); !strings.Contains(logs, "GET / HTTP/1.1") {
		t.Fatalf("nginx never saw the browser's request: %s", logs)
	}

	if err := ws.Write(ctx, websocket.MessageText, []byte(guac.Encode("disconnect"))); err != nil {
		t.Fatal(err)
	}
	gone := false
	for i := 0; i < 300 && !gone; i++ {
		ps := dbtest.Docker(t, "ps", "-a", "-q", "--filter", "label=zanskar.session="+sessionID)
		nets := dbtest.Docker(t, "network", "ls", "-q", "--filter", "label=zanskar.session="+sessionID)
		gone = ps == "" && nets == ""
		if !gone {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !gone {
		t.Fatal("the session's containers or network were left behind")
	}
	start := lastEvent(t, f, "session.start")
	var d map[string]any
	_ = json.Unmarshal(start.Details, &d)
	if d["protocol"] != "http" || d["target_id"] != tg.ID {
		t.Fatalf("session.start %v", d)
	}
}
