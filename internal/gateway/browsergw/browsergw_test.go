// SPDX-License-Identifier: Apache-2.0

package browsergw

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
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
	cs = r.Checks(context.Background())
	if cs[0].OK != true || cs[1].OK || cs[2].OK != true {
		t.Fatalf("cached runtime answer expected to stand: %+v", cs)
	}
	if probes != 1 {
		t.Fatalf("probes = %d, want the first answer kept", probes)
	}
	r.probed = r.probed.Add(-2 * probeCacheTTL)
	if cs = r.Checks(context.Background()); !cs[1].OK || probes != 2 {
		t.Fatalf("after the cache: %+v probes=%d", cs, probes)
	}
}

// DefaultBrowserImageForTest stands in for the settings default.
func DefaultBrowserImageForTest() string { return "ghcr.io/albatroxxx/zanskar-browser:test" }
