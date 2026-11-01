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
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/dbgw/dbtest"
	"github.com/albatroxxx/zanskar/internal/gateway/guac"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/policy/policytest"
	"github.com/albatroxxx/zanskar/internal/protocol"
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

// container starts an image on the default bridge and returns its name and
// its address there; it is removed with the test.
func container(t *testing.T, name string, args ...string) (containerName, ip string) {
	t.Helper()
	name += "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	dbtest.Docker(t, append([]string{"run", "-d", "--rm", "--name", name}, args...)...)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() }) // #nosec G204 -- fixed test arguments
	return name, dbtest.Docker(t, "inspect", "-f", "{{.NetworkSettings.Networks.bridge.IPAddress}}", name)
}

// realApp is an application session opened against real containers: guacd,
// the browser image, the relay and an nginx upstream, with the browser's
// first frame drawn.
type realApp struct {
	f         *connectFixture
	ws        *websocket.Conn
	nginx     string
	sessionID string
	targetID  string
	// hangUp stops the client's keepalive.
	hangUp context.CancelFunc
}

// openRealApp opens one. prepare, when set, runs on the nginx container
// before the browser fetches anything from it. Needs ZANSKAR_TEST_DOCKER=1 and
// ZANSKAR_TEST_BROWSER_IMAGE naming a built browser image.
func openRealApp(t *testing.T, ctx context.Context, prepare func(nginxName string)) *realApp {
	t.Helper()
	dbtest.RequireDocker(t)
	browserImage := os.Getenv("ZANSKAR_TEST_BROWSER_IMAGE")
	if browserImage == "" {
		t.Skip("set ZANSKAR_TEST_BROWSER_IMAGE to a built deploy/browser image")
	}
	relayImage := buildGatewayImage(t)
	nginxName, upstreamIP := container(t, "zanskar-test-nginx", "nginx:alpine")
	if prepare != nil {
		prepare(nginxName)
	}
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
	appGrant := policytest.Tagged(protocol.KindApplication, map[string]string{"app": "yes"}, "http")
	appGrant.AllowClipboard = true
	apps := policytest.Policy("apps", []policy.Subject{policytest.User(f.alice.ID)}, appGrant)
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
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws/desktop?width=1024&height=768&ticket="+tok, f.wsOptions("guacamole")) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.CloseNow() })
	// A stock client answers guacd's sync and sends nop keepalives, and guacd
	// drops a user that says nothing for fifteen seconds. The first frame can
	// take longer than that on a loaded runner, so this client keeps talking
	// until it hangs up.
	keepalive, hangUp := context.WithCancel(ctx)
	t.Cleanup(hangUp)
	go func() {
		beat := time.NewTicker(3 * time.Second)
		defer beat.Stop()
		for {
			select {
			case <-keepalive.Done():
				return
			case <-beat.C:
				_ = ws.Write(keepalive, websocket.MessageText, []byte(guac.Encode("nop")))
			}
		}
	}()

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
	return &realApp{f: f, ws: ws, nginx: nginxName, sessionID: sessionID, targetID: tg.ID, hangUp: hangUp}
}

// TestApplicationSessionThroughRealBrowser: with a real guacd, the browser
// image and an nginx as the application, an http ticket ends in pixels:
// guacd draws the browser's screen into the session's socket, the
// containers sit on the networks the design says (the browser on the
// internal network alone, the relay on it and the bridge), and the end of
// the session removes all three. Needs ZANSKAR_TEST_DOCKER=1 and
// ZANSKAR_TEST_BROWSER_IMAGE naming a built browser image.
func TestApplicationSessionThroughRealBrowser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	app := openRealApp(t, ctx, nil)
	f, ws, nginxName, sessionID, hangUp := app.f, app.ws, app.nginx, app.sessionID, app.hangUp
	tg := &target.Target{ID: app.targetID}
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
	// The request reached nginx through the relay: its log has the GET. guacd
	// draws the first pixels as soon as the VNC server paints, which can be
	// before Chromium has fetched the page, so the log is given time to
	// show it. Only this test's nginx is read, by name.
	var logs string
	for i := 0; i < 60 && !strings.Contains(logs, "GET / HTTP/1.1"); i++ {
		if i > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		logs = dbtest.Docker(t, "logs", nginxName)
	}
	if !strings.Contains(logs, "GET / HTTP/1.1") {
		// The session is ended first, so that a failing assertion does not
		// leave the handler writing to a closed database and recording.
		hangUp()
		_ = ws.Write(ctx, websocket.MessageText, []byte(guac.Encode("disconnect")))
		time.Sleep(2 * time.Second)
		t.Fatalf("nginx never saw the browser's request in 30 s: %s", logs)
	}

	hangUp()
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

// TestApplicationBrowserControls (2026-10-30, a full browser since
// 2026-10-31, ADR 0037): Chromium's own shortcuts work over guacd in the
// shipped image: Back off a blocked page, Back and Forward between pages,
// Reload, and Home to the application's start page (the Home button's
// policy). Each page reports every time it is shown, so a page restored from
// the back/forward cache counts as well as one fetched again.
func TestApplicationBrowserControls(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	app := openRealApp(t, ctx, func(nginx string) {
		page := func(name, body string) string {
			return "printf '%s' '<!doctype html><title>" + name + "</title><body>" + body + "</body>' > /usr/share/nginx/html/" + name
		}
		dbtest.Docker(t, "exec", nginx, "sh", "-c", strings.Join([]string{
			// Each page focuses its one link, so Enter follows it, and asks
			// for /shown<its path> whenever it is shown: a full browser
			// restores Back and Forward from its back/forward cache without
			// fetching the page (2026-10-31; kiosk mode fetched it again).
			page("index.html", `<a href="/two.html">two</a><script>document.querySelector("a").focus();addEventListener("pageshow",()=>fetch("/shown"+location.pathname+"?"+Date.now()))</script>`),
			page("two.html", `<a href="https://example.com/">elsewhere</a><script>document.querySelector("a").focus();addEventListener("pageshow",()=>fetch("/shown"+location.pathname+"?"+Date.now()))</script>`),
			`sed -i 's|location / {|location / { add_header Cache-Control no-store;|' /etc/nginx/conf.d/default.conf`,
			"nginx -s reload",
		}, " && "))
	})
	defer func() {
		app.hangUp()
		_ = app.ws.Write(ctx, websocket.MessageText, []byte(guac.Encode("disconnect")))
		time.Sleep(2 * time.Second)
	}()
	// count is how many times the page at path has been shown.
	count := func(path string) int {
		return strings.Count(dbtest.Docker(t, "logs", app.nginx), `"GET /shown`+path+`?`)
	}
	seen := func(path string, n int, within time.Duration) bool {
		for end := time.Now().Add(within); time.Now().Before(end); time.Sleep(250 * time.Millisecond) {
			if count(path) >= n {
				return true
			}
		}
		return false
	}
	waitFor := func(what, path string, n int) {
		t.Helper()
		if !seen(path, n, 30*time.Second) {
			t.Fatalf("%s: nginx saw GET %s %d times, want %d:\n%s", what, path, count(path), n, dbtest.Docker(t, "logs", app.nginx))
		}
	}
	keys := func(keysyms ...int) {
		t.Helper()
		for _, k := range keysyms {
			if err := app.ws.Write(ctx, websocket.MessageText, []byte(guac.Encode("key", strconv.Itoa(k), "1"))); err != nil {
				t.Fatal(err)
			}
		}
		for i := len(keysyms) - 1; i >= 0; i-- {
			if err := app.ws.Write(ctx, websocket.MessageText, []byte(guac.Encode("key", strconv.Itoa(keysyms[i]), "0"))); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	// Drain what guacd draws, so its socket never backs up while keys go in.
	go func() {
		for {
			if _, _, err := app.ws.Read(ctx); err != nil {
				return
			}
		}
	}()
	const (
		alt, enter, left, right, home, f5 = 0xffe9, 0xff0d, 0xff51, 0xff53, 0xff50, 0xffc2
	)

	waitFor("the start page", "/", 1)
	// A page is fetched before its script has focused the link; Enter is
	// pressed again until the link has been followed.
	for i := 0; i < 10 && !seen("/two.html", 1, 3*time.Second); i++ {
		keys(enter)
	}
	waitFor("following the link", "/two.html", 1)
	// The link off the application: blocked by policy, nothing reaches nginx.
	time.Sleep(2 * time.Second)
	keys(enter)
	time.Sleep(2 * time.Second)

	keys(alt, left) // the blocked page back to page two
	waitFor("Back off the blocked page", "/two.html", 2)
	keys(alt, left)
	waitFor("Back", "/", 2)
	keys(alt, right)
	waitFor("Forward", "/two.html", 3)
	keys(f5)
	waitFor("Reload", "/two.html", 4)
	// Home is also the proof that the entrypoint's managed policy is in
	// force: without HomepageLocation, Alt+Home opens the new tab page and
	// nginx sees nothing.
	keys(alt, home)
	waitFor("Home", "/", 3)
}

// TestApplicationBrowserFollowsTheScreen (2026-11-01, the live console in
// full screen: black below the page): when the session's pane changes size,
// guacd resizes the X screen, and the browser window is made that size too,
// larger and smaller again. There is no window manager in the image; the
// entrypoint does it with xdotool, which this test reads the sizes with.
func TestApplicationBrowserFollowsTheScreen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	app := openRealApp(t, ctx, nil)
	defer func() {
		app.hangUp()
		_ = app.ws.Write(ctx, websocket.MessageText, []byte(guac.Encode("disconnect")))
		time.Sleep(2 * time.Second)
	}()
	// Drain what guacd draws, so its socket never backs up.
	go func() {
		for {
			if _, _, err := app.ws.Read(ctx); err != nil {
				return
			}
		}
	}()
	browser := "zanskar-browser-" + app.sessionID
	// sizes is the X screen's size on the first line, then each visible
	// browser window's, as "width height".
	sizes := func() []string {
		out := dbtest.Docker(t, "exec", "-e", "DISPLAY=:1", browser, "sh", "-c",
			`xdotool getdisplaygeometry 2>&1; for id in $(xdotool search --onlyvisible --class chromium 2>/dev/null); do xdotool getwindowgeometry --shell "$id" | sed -n 's/^WIDTH=//p; s/^HEIGHT=//p' | tr '\n' ' '; echo; done`)
		lines := strings.Split(out, "\n")
		for i := range lines {
			lines[i] = strings.TrimSpace(lines[i])
		}
		return lines
	}
	fills := func(what string, w, h int) {
		t.Helper()
		want := strconv.Itoa(w) + " " + strconv.Itoa(h)
		var got []string
		for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(500 * time.Millisecond) {
			if got = sizes(); got[0] == want && slices.Contains(got[1:], want) {
				return
			}
		}
		t.Fatalf("%s: want the screen and a browser window at %s; screen, then windows: %q", what, want, got)
	}
	resize := func(w, h int) {
		t.Helper()
		if err := app.ws.Write(ctx, websocket.MessageText, []byte(guac.Encode("size", strconv.Itoa(w), strconv.Itoa(h)))); err != nil {
			t.Fatal(err)
		}
	}
	fills("the session's first size", 1024, 768)
	resize(1280, 960)
	fills("a larger pane, as full screen", 1280, 960)
	resize(900, 600)
	fills("a smaller pane", 900, 600)
}

// TestBrowserImageEnforcesManagedPolicy (2026-10-30, when the image moved to
// a trimmed Debian 13): the image's Chromium reads policy from
// /etc/chromium/policies/managed, where the entrypoint writes it, and blocks
// what URLBlocklist names. A data: page renders without a policy and is
// blank with one that blocks everything. The session's own policy cannot be
// probed this way: it turns developer tools off, and --dump-dom needs them.
// Needs ZANSKAR_TEST_DOCKER=1 and ZANSKAR_TEST_BROWSER_IMAGE.
func TestBrowserImageEnforcesManagedPolicy(t *testing.T) {
	dbtest.RequireDocker(t)
	image := os.Getenv("ZANSKAR_TEST_BROWSER_IMAGE")
	if image == "" {
		t.Skip("set ZANSKAR_TEST_BROWSER_IMAGE to a built deploy/browser image")
	}
	render := func(policy string) string {
		t.Helper()
		script := `mkdir -p /tmp/home && export HOME=/tmp/home
[ -z "$1" ] || printf '%s' "$1" > /etc/chromium/policies/managed/zanskar.json
exec timeout 60 chromium --headless --disable-gpu --no-sandbox --user-data-dir=/tmp/profile --dump-dom 'data:text/html,<p>rendered</p>' 2>/dev/null`
		return dbtest.Docker(t, "run", "--rm", "--network", "none", "--tmpfs", "/tmp",
			"--tmpfs", "/etc/chromium/policies/managed:uid=10001,gid=10001,mode=700",
			"--entrypoint", "sh", image, "-c", script, "probe", policy)
	}
	if got := render(""); !strings.Contains(got, "rendered") {
		t.Fatalf("Chromium did not render a page with no policy: %q", got)
	}
	if got := render(`{"URLBlocklist":["*"]}`); strings.Contains(got, "rendered") {
		t.Fatal("a policy in /etc/chromium/policies/managed did not block the page: the entrypoint's policy would not be in force")
	}
}

// TestBrowserEntrypointPolicy (ADR 0037): the entrypoint writes a policy
// Chromium can read (valid JSON, assembled by the shell) that keeps the
// browser on the application's origin with its internal pages, files,
// javascript: and view-source: blocked by name, gives every new tab and
// Home the application, and opens developer tools only when the session's
// grant does. Needs ZANSKAR_TEST_DOCKER=1 and ZANSKAR_TEST_BROWSER_IMAGE.
func TestBrowserEntrypointPolicy(t *testing.T) {
	dbtest.RequireDocker(t)
	image := os.Getenv("ZANSKAR_TEST_BROWSER_IMAGE")
	if image == "" {
		t.Skip("set ZANSKAR_TEST_BROWSER_IMAGE to a built deploy/browser image")
	}
	written := func(devtools string) map[string]any {
		t.Helper()
		out := dbtest.Docker(t, "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
			"--tmpfs", "/etc/chromium/policies/managed:uid=10001,gid=10001,mode=700",
			"-e", "APP_URL=http://wiki.internal:8080/", "-e", "APP_ORIGIN=http://wiki.internal:8080",
			"-e", "RESOLVER_RULES=MAP * ~NOTFOUND", "-e", "VNC_PASSWORD=probe123", "-e", "DEVTOOLS="+devtools,
			"--entrypoint", "sh", image, "-c",
			"/entrypoint.sh >/dev/null 2>&1 & for i in $(seq 50); do [ -s /etc/chromium/policies/managed/zanskar.json ] && break; sleep 0.1; done; cat /etc/chromium/policies/managed/zanskar.json")
		var p map[string]any
		if err := json.Unmarshal([]byte(out), &p); err != nil {
			t.Fatalf("DEVTOOLS=%s: the policy is not JSON (%v):\n%s", devtools, err, out)
		}
		return p
	}
	list := func(p map[string]any, key string) []string {
		var out []string
		for _, v := range p[key].([]any) {
			out = append(out, v.(string))
		}
		return out
	}
	off := written("false")
	if off["DeveloperToolsAvailability"] != float64(2) || !slices.Contains(list(off, "URLBlocklist"), "devtools://*") || slices.Contains(list(off, "URLAllowlist"), "devtools://*") {
		t.Fatalf("developer tools must be off and devtools:// blocked: %v", off)
	}
	for _, blocked := range []string{"*", "chrome://*", "file://*", "javascript:*", "view-source:*"} {
		if !slices.Contains(list(off, "URLBlocklist"), blocked) {
			t.Errorf("%s is not blocked: %v", blocked, off["URLBlocklist"])
		}
	}
	if !slices.Equal(list(off, "URLAllowlist"), []string{"http://wiki.internal:8080"}) {
		t.Errorf("allowlist: %v", off["URLAllowlist"])
	}
	if off["NewTabPageLocation"] != "http://wiki.internal:8080/" || off["HomepageLocation"] != "http://wiki.internal:8080/" || off["ShowHomeButton"] != true || off["DownloadRestrictions"] != float64(3) {
		t.Errorf("start pages, Home or downloads: %v", off)
	}
	on := written("true")
	if on["DeveloperToolsAvailability"] != float64(1) || !slices.Contains(list(on, "URLAllowlist"), "devtools://*") || slices.Contains(list(on, "URLBlocklist"), "devtools://*") {
		t.Fatalf("developer tools must be on when granted: %v", on)
	}
	if !slices.Contains(list(on, "URLBlocklist"), "chrome://*") {
		t.Errorf("granting developer tools must not open chrome:// pages: %v", on["URLBlocklist"])
	}
}
