// SPDX-License-Identifier: Apache-2.0

// Package browsergw opens an application in an isolated browser (ADR 0034).
// Per session it creates a private, internal Docker network, a relay
// container (the gateway's own image running `zanskar apprelay`) that is
// also attached to the runtime's default bridge, and a browser container
// (Chromium in kiosk mode behind a VNC server) on the internal network
// alone. The relay forwards the upstream's one port to the resolved upstream
// address and the browser's VNC port to the bridge side, where guacd takes
// it; the browser's resolver maps the upstream's name to the relay and
// everything else to nothing. What guacd draws is bridged, recorded and
// torn down by the desktop path, unchanged; Close removes the three objects
// and the reaper in package containers removes what a crash left.
package browsergw

import (
	"context"
	"crypto/rand"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/gateway/apprelay"
	"github.com/albatroxxx/zanskar/internal/gateway/containers"
)

// seccompProfile is Docker's default seccomp profile (moby/profiles,
// seccomp/default.json at commit 6fe7deb1b9fb, 2026-09-17) plus one rule allowing clone, clone3, unshare, setns
// and chroot without CAP_SYS_ADMIN: the calls Chromium's own sandbox makes
// to put each renderer in user, pid and network namespaces of its own and
// chroot it to nothing. Everything else the default refuses stays refused.
//
//go:embed seccomp.json
var seccompProfile []byte

// SeccompFile is the profile's name under the state directory.
const SeccompFile = "browser-seccomp.json"

// Spec is one application session's browser.
type Spec struct {
	SessionID string
	// Upstream is the application's origin, scheme://host[:port], as the
	// target stores it; UpstreamIP is its host resolved by the gateway
	// through the address rules, the only address the relay dials.
	Upstream   *url.URL
	UpstreamIP net.IP
	// TLSCA is an optional PEM bundle an https upstream is verified against,
	// installed in the browser's certificate store for the session.
	TLSCA string
	// Width and Height are the screen, the size the user's window had.
	Width, Height int
	// DevTools opens Chromium's developer tools to this session (ADR 0037):
	// a grant allows it, and the browser is this session's alone.
	DevTools bool
	// BrowserImage and RelayImage are the two images; the relay's is the
	// gateway's own.
	BrowserImage, RelayImage string
	// StateDir is where the seccomp profile is written for the daemon to
	// read.
	StateDir string
}

// Session is a running browser and where guacd reaches it.
type Session struct {
	// VNCAddr is host:port on the runtime's default bridge; Password is
	// the VNC password made for this session.
	VNCAddr  string
	Password string
	// InternalIP is the relay's address on the session network, the one
	// the browser's resolver maps the upstream's name to.
	InternalIP string
	closers    []func()
}

// Close removes the session's containers and network, newest first. Safe
// to call more than once.
func (s *Session) Close() {
	for i := len(s.closers) - 1; i >= 0; i-- {
		s.closers[i]()
	}
	s.closers = nil
}

// names returns the per-session Docker object names.
func names(sessionID string) (network, relay, browser string) {
	return "zanskar-net-" + sessionID, "zanskar-apprelay-" + sessionID, "zanskar-browser-" + sessionID
}

// vncPassword makes an 8-character password, the most VNC authentication
// uses, from letters and digits.
func vncPassword() (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}

// upstreamPort is the port the browser connects to: the one in the
// upstream, else the scheme's.
func upstreamPort(u *url.URL) int {
	if p := u.Port(); p != "" {
		n, _ := strconv.Atoi(p)
		return n
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

// relayArgs builds the relay's `docker run` and the table it reads by name;
// subnet is the session network's, so the relay knows which of its
// addresses is the internal one once the bridge is attached.
func relayArgs(spec Spec, network, relayName, browserName, subnet string) (args, env []string, err error) {
	port := upstreamPort(spec.Upstream)
	cfg := apprelay.Config{Forwards: []apprelay.Forward{
		{Listen: "internal:" + strconv.Itoa(port), To: net.JoinHostPort(spec.UpstreamIP.String(), strconv.Itoa(port))},
		{Listen: ":5900", To: net.JoinHostPort(browserName, "5900"), Once: true, Retry: apprelay.Duration(20 * time.Second)},
	}, InternalSubnet: subnet}
	raw, err := marshal(cfg)
	if err != nil {
		return nil, nil, err
	}
	args = append([]string{"run", "-d", "--rm", "--name", relayName, "--network", network}, containers.Labels(spec.SessionID)...)
	args = append(args,
		"--security-opt", "no-new-privileges", "--cap-drop", "ALL", "--read-only",
		// The gateway's binary carries the console; it maps about 70 MB at
		// start, and 64m had the kernel kill it before it listened.
		"--pids-limit", "64", "--memory", "192m",
		"-e", "ZANSKAR_APPRELAY",
		spec.RelayImage, "apprelay",
	)
	return args, []string{"ZANSKAR_APPRELAY=" + raw}, nil
}

// browserArgs builds the browser's `docker run` and its environment: the
// policy directory is a tmpfs owned by the browser's user (the image's
// directory is root's, and a tmpfs takes the mode of what it covers), the
// URL, the origin the policy allows, the resolver rule that maps the
// upstream's name to the relay and everything else to nothing, the VNC
// password, the screen and the CA bundle. The values travel by name; the
// argument vector shows only the names.
func browserArgs(spec Spec, network, browserName, relayInternalIP, password, seccompPath string) (args, env []string) {
	args = append([]string{"run", "-d", "--rm", "--name", browserName, "--network", network}, containers.Labels(spec.SessionID)...)
	args = append(args,
		"--read-only", "--tmpfs", "/tmp:rw,size=512m", "--tmpfs", "/etc/chromium/policies/managed:rw,size=1m,uid=10001,gid=10001,mode=700",
		"--security-opt", "no-new-privileges", "--security-opt", "seccomp="+seccompPath, "--cap-drop", "ALL",
		"--pids-limit", "512", "--memory", "1536m", "--cpus", "2",
		"-e", "APP_URL", "-e", "APP_ORIGIN", "-e", "RESOLVER_RULES", "-e", "VNC_PASSWORD", "-e", "SCREEN_W", "-e", "SCREEN_H", "-e", "CA_PEM",
		"-e", "DEVTOOLS",
		spec.BrowserImage,
	)
	origin := spec.Upstream.Scheme + "://" + spec.Upstream.Host
	env = []string{
		"APP_URL=" + origin + "/",
		"APP_ORIGIN=" + origin,
		"RESOLVER_RULES=MAP " + spec.Upstream.Hostname() + " " + relayInternalIP + ", MAP * ~NOTFOUND",
		"VNC_PASSWORD=" + password,
		"SCREEN_W=" + strconv.Itoa(spec.Width),
		"SCREEN_H=" + strconv.Itoa(spec.Height),
		"CA_PEM=" + spec.TLSCA,
		"DEVTOOLS=" + strconv.FormatBool(spec.DevTools),
	}
	return args, env
}

// writeSeccomp puts the profile under the state directory, rewriting it
// when its content differs, and returns its path. The daemon, not the
// service user, reads it, so it is world-readable and holds no secret.
func writeSeccomp(stateDir string) (string, error) {
	path := filepath.Join(stateDir, SeccompFile)
	if cur, err := os.ReadFile(path); err == nil && string(cur) == string(seccompProfile) { // #nosec G304 -- the gateway's own state directory
		return path, nil
	}
	if err := os.WriteFile(path, seccompProfile, 0o644); err != nil { // #nosec G306 -- the daemon reads it; nothing secret in it
		return "", fmt.Errorf("browsergw: write seccomp profile: %w", err)
	}
	return path, nil
}

// networkSubnet reads the session network's IPv4 subnet.
func networkSubnet(ctx context.Context, docker, network string) (string, error) {
	out, err := containers.Output(ctx, docker, nil, "network", "inspect", "-f", `{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}`, network)
	if err != nil {
		return "", fmt.Errorf("browsergw: network subnet: %w", err)
	}
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if ip, _, err := net.ParseCIDR(line); err == nil && ip.To4() != nil {
			return line, nil
		}
	}
	return "", fmt.Errorf("browsergw: network %s has no IPv4 subnet (%q)", network, strings.TrimSpace(out))
}

// inspectNetworks reads a container's address on each network it is
// attached to.
func inspectNetworks(ctx context.Context, docker, name string) (map[string]string, error) {
	out, err := containers.Output(ctx, docker, nil, "inspect", "-f", `{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}}{{"\n"}}{{end}}`, name)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for line := range strings.SplitSeq(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && v != "" {
			m[k] = v
		}
	}
	return m, nil
}

// Start creates the session's network, relay and browser, waits for the
// browser's VNC server to listen, and returns where guacd reaches it. A
// failure removes whatever was made. docker is the container CLI, empty
// for "docker" on PATH.
func Start(ctx context.Context, log *slog.Logger, docker string, spec Spec) (*Session, error) {
	if log == nil {
		log = slog.Default()
	}
	if docker == "" {
		docker = "docker"
	}
	if spec.Upstream == nil || spec.UpstreamIP == nil || spec.SessionID == "" || spec.BrowserImage == "" || spec.RelayImage == "" {
		return nil, errors.New("browsergw: incomplete spec")
	}
	if spec.Width <= 0 || spec.Height <= 0 {
		spec.Width, spec.Height = 1280, 800
	}
	password, err := vncPassword()
	if err != nil {
		return nil, err
	}
	seccompPath, err := writeSeccomp(spec.StateDir)
	if err != nil {
		return nil, err
	}
	network, relay, browser := names(spec.SessionID)
	// The images come first, under a deadline of their own: the first
	// session on a host pulls the relay and the browser (hundreds of
	// megabytes), which the set-up's budget of seconds is not for.
	for _, img := range []string{spec.RelayImage, spec.BrowserImage} {
		if err := containers.EnsureImage(ctx, log, docker, img); err != nil {
			return nil, err
		}
	}
	// Set-up and teardown are detached from the session's cancellation (but
	// keep its values) so teardown still runs after the session ends.
	detached := context.WithoutCancel(ctx)
	suCtx, suCancel := context.WithTimeout(detached, 45*time.Second)
	defer suCancel()
	s := &Session{Password: password}
	fail := func(err error) (*Session, error) {
		s.Close()
		return nil, err
	}
	rm := func(args ...string) func() {
		return func() {
			tdCtx, cancel := context.WithTimeout(detached, 15*time.Second)
			defer cancel()
			_ = containers.Run(tdCtx, docker, nil, args...)
		}
	}

	isolated := !containers.Podman(docker)
	err = containers.Run(suCtx, docker, nil, containers.NetworkArgs(spec.SessionID, network, isolated)...)
	if err != nil && isolated {
		log.Warn("session network without the isolated gateway mode: the gateway host's own address stays reachable from the browser container (Docker 28.1 or newer fixes this)", "session", spec.SessionID, "err", err)
		err = containers.Run(suCtx, docker, nil, containers.NetworkArgs(spec.SessionID, network, false)...)
	}
	if err != nil {
		return nil, err
	}
	s.closers = append(s.closers, rm("network", "rm", network))
	subnet, err := networkSubnet(suCtx, docker, network)
	if err != nil {
		return fail(err)
	}

	rargs, renv, err := relayArgs(spec, network, relay, browser, subnet)
	if err != nil {
		return fail(err)
	}
	if err := containers.Run(suCtx, docker, renv, rargs...); err != nil {
		return fail(fmt.Errorf("browsergw: start relay: %w", err))
	}
	s.closers = append(s.closers, rm("rm", "-f", relay))
	// The relay alone gets a way out: the runtime's default bridge, through
	// which it reaches the upstream and on which guacd reaches it.
	if err := containers.Run(suCtx, docker, nil, "network", "connect", containers.EgressNetwork(docker), relay); err != nil {
		return fail(fmt.Errorf("browsergw: relay egress: %w", err))
	}
	nets, err := inspectNetworks(suCtx, docker, relay)
	if err != nil {
		return fail(fmt.Errorf("browsergw: relay addresses: %w", err))
	}
	s.InternalIP = nets[network]
	bridgeIP := nets[containers.EgressNetwork(docker)]
	if s.InternalIP == "" || bridgeIP == "" {
		return fail(fmt.Errorf("browsergw: relay has no address on %s or %s (%v)", network, containers.EgressNetwork(docker), nets))
	}
	s.VNCAddr = net.JoinHostPort(bridgeIP, "5900")

	bargs, benv := browserArgs(spec, network, browser, s.InternalIP, password, seccompPath)
	if err := containers.Run(suCtx, docker, benv, bargs...); err != nil {
		return fail(fmt.Errorf("browsergw: start browser: %w", err))
	}
	s.closers = append(s.closers, rm("rm", "-f", browser))
	// The VNC server takes a moment; the entrypoint marks the moment it
	// listens, and guacd is only dialled after it.
	if err := waitReady(suCtx, docker, browser); err != nil {
		return fail(err)
	}
	return s, nil
}

// waitReady polls the browser container for the entrypoint's ready mark.
func waitReady(ctx context.Context, docker, browser string) error {
	deadline := time.Now().Add(20 * time.Second)
	for {
		if err := containers.Run(ctx, docker, nil, "exec", browser, "test", "-f", "/tmp/ready"); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("browsergw: the browser's VNC server did not come up in time")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}
