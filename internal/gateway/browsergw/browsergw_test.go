// SPDX-License-Identifier: Apache-2.0

package browsergw

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func spec(t *testing.T) Spec {
	t.Helper()
	u, err := url.Parse("http://wiki.internal:8080")
	if err != nil {
		t.Fatal(err)
	}
	return Spec{SessionID: "s1", Upstream: u, UpstreamIP: net.ParseIP("10.0.0.50"), Width: 1440, Height: 900,
		BrowserImage: "ghcr.io/albatroxxx/zanskar-browser@sha256:" + strings.Repeat("ab", 32), RelayImage: "ghcr.io/albatroxxx/zanskar:1.7.0", StateDir: t.TempDir()}
}

// TestRelayArgs: the relay runs the gateway's own image hardened, with its
// table by name in the environment: the upstream's port bound to the
// internal side and forwarded to the resolved address, and the VNC port
// taken once; nothing of the table is in the argument vector.
func TestRelayArgs(t *testing.T) {
	args, env, err := relayArgs(spec(t), "zanskar-net-s1", "zanskar-apprelay-s1", "zanskar-browser-s1", "172.30.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"--network zanskar-net-s1", "--label zanskar.managed=1", "--label zanskar.session=s1",
		"--security-opt no-new-privileges", "--cap-drop ALL", "--read-only", "-e ZANSKAR_APPRELAY", "ghcr.io/albatroxxx/zanskar:1.7.0 apprelay"} {
		if !strings.Contains(joined, want) {
			t.Errorf("relay args miss %q: %s", want, joined)
		}
	}
	if strings.Contains(joined, "10.0.0.50") || strings.Contains(joined, "5900") {
		t.Errorf("the table leaked into argv: %s", joined)
	}
	if len(env) != 1 || !strings.HasPrefix(env[0], "ZANSKAR_APPRELAY=") {
		t.Fatalf("env: %v", env)
	}
	table := env[0]
	for _, want := range []string{`"listen":"internal:8080"`, `"to":"10.0.0.50:8080"`, `"listen":":5900"`, `"to":"zanskar-browser-s1:5900"`, `"once":true`, `"retry":"20s"`, `"internal_subnet":"172.30.0.0/16"`} {
		if !strings.Contains(table, want) {
			t.Errorf("table misses %s: %s", want, table)
		}
	}
	// An https upstream without a port is 443.
	s := spec(t)
	s.Upstream, _ = url.Parse("https://grafana.internal")
	_, env, _ = relayArgs(s, "n", "r", "b", "172.30.0.0/16")
	if !strings.Contains(env[0], `"listen":"internal:443"`) || !strings.Contains(env[0], `"to":"10.0.0.50:443"`) {
		t.Errorf("https default port: %s", env[0])
	}
}

// TestBrowserArgs: the browser runs read-only, without capabilities, under
// the seccomp profile and pid, memory and cpu limits, on the session
// network only; its URL, origin, resolver rule, VNC password, screen and CA
// travel by name, never in the argument vector.
func TestBrowserArgs(t *testing.T) {
	s := spec(t)
	s.TLSCA = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"
	args, env := browserArgs(s, "zanskar-net-s1", "zanskar-browser-s1", "172.30.0.2", "p4ssw0rd", "/var/lib/zanskar/browser-seccomp.json")
	joined := strings.Join(args, " ")
	for _, want := range []string{"--network zanskar-net-s1", "--read-only", "--tmpfs /tmp:rw,size=512m", "--tmpfs /etc/chromium/policies/managed:rw,size=1m,uid=10001,gid=10001,mode=700",
		"--security-opt no-new-privileges", "--security-opt seccomp=/var/lib/zanskar/browser-seccomp.json", "--cap-drop ALL",
		"--pids-limit 512", "--memory 1536m", "--cpus 2", "-e APP_URL -e APP_ORIGIN -e RESOLVER_RULES -e VNC_PASSWORD -e SCREEN_W -e SCREEN_H -e CA_PEM",
		"--label zanskar.session=s1", s.BrowserImage} {
		if !strings.Contains(joined, want) {
			t.Errorf("browser args miss %q: %s", want, joined)
		}
	}
	for _, leak := range []string{"p4ssw0rd", "wiki.internal", "172.30.0.2", "BEGIN CERTIFICATE", "--network bridge"} {
		if strings.Contains(joined, leak) {
			t.Errorf("%q in argv: %s", leak, joined)
		}
	}
	got := strings.Join(env, "\n")
	for _, want := range []string{"APP_URL=http://wiki.internal:8080/", "APP_ORIGIN=http://wiki.internal:8080",
		"RESOLVER_RULES=MAP wiki.internal 172.30.0.2, MAP * ~NOTFOUND", "VNC_PASSWORD=p4ssw0rd", "SCREEN_W=1440", "SCREEN_H=900", "CA_PEM=-----BEGIN CERTIFICATE-----"} {
		if !strings.Contains(got, want) {
			t.Errorf("env misses %q: %s", want, got)
		}
	}
}

// TestSeccompProfileIsDefaultPlusNamespaces: the embedded profile is a
// seccomp profile whose default action refuses, with one rule that allows
// exactly the namespace and chroot calls Chromium's sandbox needs, and it
// is written under the state directory once and rewritten when changed.
func TestSeccompProfileIsDefaultPlusNamespaces(t *testing.T) {
	p := string(seccompProfile)
	if !strings.Contains(p, `"defaultAction": "SCMP_ACT_ERRNO"`) {
		t.Fatal("the profile does not refuse by default")
	}
	for _, call := range []string{"clone", "clone3", "unshare", "setns", "chroot"} {
		if !strings.Contains(p, `"`+call+`"`) {
			t.Errorf("profile lacks %s", call)
		}
	}
	if strings.Contains(p, `"mount"`) && strings.Contains(p, `"names": ["mount"]`) {
		t.Error("mount must not be allowed outright")
	}
	dir := t.TempDir()
	path, err := writeSeccomp(dir)
	if err != nil || path != filepath.Join(dir, SeccompFile) {
		t.Fatalf("write: %s %v", path, err)
	}
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeSeccomp(dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != p { // #nosec G304 -- test temp dir
		t.Fatal("a changed profile was not rewritten")
	}
}

// stubDocker writes a stand-in docker CLI that records every call to a log
// and answers `inspect` with two addresses, so Start can be driven without
// a daemon.
func stubDocker(t *testing.T) (docker, calls string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in docker CLI is a shell script")
	}
	dir := t.TempDir()
	calls = filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + calls + "'\n" +
		"if [ \"$1\" = inspect ]; then printf 'bridge=172.17.0.9\\nzanskar-net-s1=172.30.0.2\\n'; fi\n" +
		"if [ \"$1\" = network ] && [ \"$2\" = inspect ]; then printf '172.30.0.0/16\\n'; fi\n" +
		"if [ \"$1\" = run ]; then echo \"ENV ZANSKAR_APPRELAY=$ZANSKAR_APPRELAY VNC_PASSWORD=$VNC_PASSWORD\" >> '" + calls + "'; fi\nexit 0\n"
	docker = filepath.Join(dir, "docker")
	if err := os.WriteFile(docker, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test stub
		t.Fatal(err)
	}
	return docker, calls
}

// TestStartOrdersAndTearsDown: Start creates the network, the relay, the
// relay's egress, reads the relay's addresses, starts the browser with the
// relay's internal address in its resolver rule, waits for the ready mark,
// and hands guacd the relay's bridge address; Close removes the three in
// reverse. The values the containers read travel in the environment.
func TestStartOrdersAndTearsDown(t *testing.T) {
	docker, calls := stubDocker(t)
	s, err := Start(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), docker, spec(t))
	if err != nil {
		t.Fatal(err)
	}
	if s.VNCAddr != "172.17.0.9:5900" || s.InternalIP != "172.30.0.2" || len(s.Password) != 8 {
		t.Fatalf("session: %+v", s)
	}
	s.Close()
	s.Close()
	b, _ := os.ReadFile(calls) // #nosec G304 -- test temp dir
	log := string(b)
	order := []string{
		"image inspect --format {{.Id}} " + spec(t).RelayImage,
		"image inspect --format {{.Id}} " + spec(t).BrowserImage,
		"network create --internal -o com.docker.network.bridge.gateway_mode_ipv4=isolated --label zanskar.managed=1 --label zanskar.session=s1 zanskar-net-s1",
		"network inspect -f",
		"run -d --rm --name zanskar-apprelay-s1 --network zanskar-net-s1",
		"ENV ZANSKAR_APPRELAY={\"forwards\"",
		"\"internal_subnet\":\"172.30.0.0/16\"",
		"network connect bridge zanskar-apprelay-s1",
		"inspect -f",
		"run -d --rm --name zanskar-browser-s1 --network zanskar-net-s1",
		"VNC_PASSWORD=" + s.Password,
		"exec zanskar-browser-s1 test -f /tmp/ready",
		"rm -f zanskar-browser-s1",
		"rm -f zanskar-apprelay-s1",
		"network rm zanskar-net-s1",
	}
	at := 0
	for _, want := range order {
		i := strings.Index(log[at:], want)
		if i < 0 {
			t.Fatalf("call %q missing or out of order after offset %d:\n%s", want, at, log)
		}
		at += i + len(want)
	}
	if strings.Count(log, "rm -f zanskar-browser-s1") != 1 {
		t.Fatal("Close twice removed twice")
	}
	if _, err := os.Stat(filepath.Join(spec(t).StateDir, SeccompFile)); err == nil {
		t.Fatal("the profile went to a different directory than the spec's")
	}
}

// TestStartPullsAbsentImages: an image the host lacks is pulled before any
// session object is made; a pull that fails makes nothing.
func TestStartPullsAbsentImages(t *testing.T) {
	docker, calls := stubDocker(t)
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + calls + "'\n" +
		"if [ \"$1\" = image ]; then exit 1; fi\n" +
		"if [ \"$1\" = pull ]; then exit ${PULL_EXIT:-0}; fi\n" +
		"if [ \"$1\" = inspect ]; then printf 'bridge=172.17.0.9\\nzanskar-net-s1=172.30.0.2\\n'; fi\n" +
		"if [ \"$1\" = network ] && [ \"$2\" = inspect ]; then printf '172.30.0.0/16\\n'; fi\nexit 0\n"
	if err := os.WriteFile(docker, []byte(script), 0o700); err != nil { // #nosec G306 -- test stub
		t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := Start(context.Background(), quiet, docker, spec(t))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	b, _ := os.ReadFile(calls) // #nosec G304 -- test temp dir
	log := string(b)
	pull := strings.Index(log, "pull --quiet "+spec(t).BrowserImage)
	run := strings.Index(log, "network create")
	if pull < 0 || run < 0 || pull > run || !strings.Contains(log, "pull --quiet "+spec(t).RelayImage) {
		t.Fatalf("both images are pulled before the network is made:\n%s", log)
	}
	// The child gets none of the test's environment (that is the point of
	// containers.ChildEnv), so the failing pull is a second script.
	docker2, calls2 := stubDocker(t)
	failing := strings.ReplaceAll(strings.ReplaceAll(script, calls, calls2), "exit ${PULL_EXIT:-0}", "exit 1")
	if err := os.WriteFile(docker2, []byte(failing), 0o700); err != nil { // #nosec G306 -- test stub
		t.Fatal(err)
	}
	if _, err := Start(context.Background(), quiet, docker2, spec(t)); err == nil || !strings.Contains(err.Error(), "pull") {
		t.Fatalf("a failed pull started a session: %v", err)
	}
	if b, _ := os.ReadFile(calls2); strings.Contains(string(b), "network create") { // #nosec G304 -- test temp dir
		t.Fatalf("a session object was made after a failed pull:\n%s", b)
	}
}

// TestStartFailureRemovesWhatItMade: a relay that cannot start leaves no
// network behind.
func TestStartFailureRemovesWhatItMade(t *testing.T) {
	docker, calls := stubDocker(t)
	if err := os.WriteFile(docker, []byte("#!/bin/sh\necho \"$*\" >> '"+calls+"'\nif [ \"$1\" = run ]; then exit 1; fi\nexit 0\n"), 0o700); err != nil { // #nosec G306 -- test stub
		t.Fatal(err)
	}
	if _, err := Start(context.Background(), nil, docker, spec(t)); err == nil {
		t.Fatal("a failed relay start succeeded")
	}
	b, _ := os.ReadFile(calls) // #nosec G304 -- test temp dir
	if !strings.Contains(string(b), "network rm zanskar-net-s1") {
		t.Fatalf("the network was left behind:\n%s", b)
	}
}

// TestStartRefusesIncompleteSpec: no image, no upstream or no address is
// refused before any container is made.
func TestStartRefusesIncompleteSpec(t *testing.T) {
	docker, calls := stubDocker(t)
	for _, mut := range []func(*Spec){func(s *Spec) { s.BrowserImage = "" }, func(s *Spec) { s.RelayImage = "" }, func(s *Spec) { s.UpstreamIP = nil }, func(s *Spec) { s.Upstream = nil }} {
		s := spec(t)
		mut(&s)
		if _, err := Start(context.Background(), nil, docker, s); err == nil {
			t.Fatal("an incomplete spec started")
		}
	}
	if _, err := os.Stat(calls); err == nil {
		t.Fatal("docker was called for an incomplete spec")
	}
}

// TestReadinessChecks: each prerequisite is reported with its state and
// what to do; the runtime probe's answer is kept for a while.
func TestReadinessChecks(t *testing.T) {
	probes := 0
	r := &Readiness{Guacd: func() string { return "" }, BrowserImage: func() string { return "" }, Docker: "podman",
		Probe: func(context.Context) error { probes++; return os.ErrPermission }}
	cs := r.Checks(context.Background())
	if len(cs) != 3 || cs[0].Key != "guacd" || cs[0].OK || cs[1].Key != "runtime" || cs[1].OK || cs[2].Key != "image" || cs[2].OK {
		t.Fatalf("nothing set: %+v", cs)
	}
	if !strings.Contains(cs[1].Detail, "podman") || !strings.Contains(cs[1].Detail, "docker group") {
		t.Fatalf("runtime detail: %s", cs[1].Detail)
	}
	r.Guacd = func() string { return "127.0.0.1:4822" }
	r.BrowserImage = DefaultBrowserImageForTest
	r.Probe = func(context.Context) error { probes++; return nil }
	inspects := 0
	r.Inspect = func(_ context.Context, image string) error {
		inspects++
		if image != DefaultBrowserImageForTest() {
			t.Errorf("inspected %q", image)
		}
		return os.ErrNotExist
	}
	cs = r.Checks(context.Background())
	if cs[0].OK != true || cs[1].OK || cs[2].OK != true || inspects != 0 {
		t.Fatalf("cached runtime answer expected to stand, and the image not asked about until the runtime answers: %+v inspects=%d", cs, inspects)
	}
	if probes != 1 {
		t.Fatalf("probes = %d, want the first answer kept", probes)
	}
	r.probed = r.probed.Add(-2 * probeCacheTTL)
	if cs = r.Checks(context.Background()); !cs[1].OK || probes != 2 {
		t.Fatalf("after the cache: %+v probes=%d", cs, probes)
	}
	// With the runtime answering, an image the host lacks is named with the
	// pull to run, and passes: the first session pulls it, so it does not
	// hold back adding an application. The answer is kept like the probe's.
	if !cs[2].OK || !strings.Contains(cs[2].Detail, "not pulled yet") || !strings.Contains(cs[2].Detail, "podman pull "+DefaultBrowserImageForTest()) || inspects != 1 {
		t.Fatalf("absent image: %+v inspects=%d", cs[2], inspects)
	}
	if _ = r.Checks(context.Background()); inspects != 1 {
		t.Fatalf("inspect not cached: %d", inspects)
	}
	r.inspected = r.inspected.Add(-2 * probeCacheTTL)
	r.Inspect = func(context.Context, string) error { inspects++; return nil }
	if cs = r.Checks(context.Background()); !cs[2].OK || !strings.Contains(cs[2].Detail, "(on this host)") || inspects != 2 {
		t.Fatalf("present image: %+v inspects=%d", cs[2], inspects)
	}
}

// DefaultBrowserImageForTest stands in for the settings default.
func DefaultBrowserImageForTest() string { return "ghcr.io/albatroxxx/zanskar-browser:test" }

// TestReadinessProbesTheDaemonNotInfo (2026-10-30): on a host where
// sessions ran fine the checklist said the runtime was unreachable, because
// it asked `docker info`, which fails on things a session never touches (a
// broken CLI plugin, a slow registry lookup). The probe asks the daemon its
// version, the one round trip a session needs, through the real command.
// The stand-in fails `version` given a format, as a local Podman does for a
// template naming .Server (it has no server part): the probe must not ask.
func TestReadinessProbesTheDaemonNotInfo(t *testing.T) {
	dir := t.TempDir()
	fake := dir + "/docker"
	script := "#!/bin/sh\ncase \"$1\" in\n  version) [ $# -eq 1 ] || { echo 'template: version:1:9: executing at <.Server.Version>: nil pointer' >&2; exit 125; }; echo 27.3.1 ;;\n  info) echo 'errors pretty printing info' >&2; exit 1 ;;\n  *) exit 3 ;;\nesac\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	r := &Readiness{Guacd: func() string { return "127.0.0.1:4822" }, BrowserImage: func() string { return "" }, Docker: fake}
	if cs := r.Checks(context.Background()); !cs[1].OK {
		t.Fatalf("a daemon that answers its version is reachable: %+v", cs[1])
	}
}

// TestReadinessWithTheDefaultCLI (2026-10-30): with ZANSKAR_DOCKER_PATH
// unset the probe ran exec("") and the live checklist said "docker
// version: exec: no command", keeping Add application away on every
// default install; sessions worked, as their callers defaulted the name
// themselves. The empty path is "docker" on PATH, as everywhere else.
func TestReadinessWithTheDefaultCLI(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\n[ \"$1\" = version ] && { echo 27.3.1; exit 0; }\n[ \"$1\" = image ] && exit 0\nexit 3\n"
	if err := os.WriteFile(dir+"/docker", []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	r := &Readiness{Guacd: func() string { return "127.0.0.1:4822" }, BrowserImage: DefaultBrowserImageForTest, Docker: ""}
	cs := r.Checks(context.Background())
	if !cs[1].OK || cs[1].Detail != "docker answers" {
		t.Fatalf("the runtime with no path set: %+v", cs[1])
	}
	if !strings.HasSuffix(cs[2].Detail, "(on this host)") {
		t.Fatalf("the image check runs the same CLI: %+v", cs[2])
	}
}

// TestRuntimeAdviceSaysWhy: a failed probe names its cause and the fix for
// it, never the same sentence whatever went wrong.
func TestRuntimeAdviceSaysWhy(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{exec.ErrNotFound, "not installed"},
		{errors.New(`docker version: exit status 1: permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock`), "restart the service so the group applies"},
		{errors.New(`docker version: exit status 1: Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?`), "daemon is not running"},
		{context.DeadlineExceeded, "within 10 seconds"},
		{errors.New("docker version: exit status 125: something new\nand more"), "cannot use docker: docker version: exit status 125: something new"},
	} {
		got := runtimeAdvice("docker", tc.err)
		if !strings.Contains(got, tc.want) || strings.Contains(got, "and more") {
			t.Errorf("%v: %q, want it to say %q", tc.err, got, tc.want)
		}
	}
}

// TestReadinessServeFresh (2026-10-30): the Applications page offers Add only
// when ready is true, and its Check again asks with fresh=1, which must not
// read the runtime's answer from before an operator's fix.
func TestReadinessServeFresh(t *testing.T) {
	probes, broken := 0, true
	r := &Readiness{Guacd: func() string { return "127.0.0.1:4822" }, BrowserImage: DefaultBrowserImageForTest, Docker: "docker",
		Probe: func(context.Context) error {
			probes++
			if broken {
				return errors.New("docker version: exit status 1: Cannot connect to the Docker daemon")
			}
			return nil
		},
		Inspect: func(context.Context, string) error { return os.ErrNotExist }}
	ask := func(query string) (ready bool) {
		t.Helper()
		rec := httptest.NewRecorder()
		r.serve(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/applications/readiness"+query, nil))
		var out struct {
			Ready bool `json:"ready"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Ready
	}
	if ask("") {
		t.Fatal("ready with the runtime down")
	}
	broken = false
	if ask("") || probes != 1 {
		t.Fatalf("a plain read within the cache keeps the old answer: probes=%d", probes)
	}
	// Fixed, and asked afresh: ready, although the image is not pulled yet.
	if !ask("?fresh=1") || probes != 2 {
		t.Fatalf("fresh=1 must probe again and pass: probes=%d", probes)
	}
}
