// SPDX-License-Identifier: Apache-2.0

// Package apprelay is the relay beside an application session (ADR 0034):
// a TCP forwarder with a fixed table. The gateway starts its own image with
// `zanskar apprelay` on the session's internal network and then attaches it
// to the runtime's default bridge, so it is the one thing on both. It
// forwards the upstream's port, bound to its internal-network address only,
// to the resolved upstream address, so the browser container reaches that
// one application and nothing else; and it forwards the browser's VNC port
// to the bridge side for guacd, taking exactly one connection there. The
// table arrives as one JSON document in ZANSKAR_APPRELAY, never in argv.
package apprelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Forward is one listener and where its connections go.
type Forward struct {
	// Listen is "internal:<port>", bound to the relay's one address at
	// start (its internal-network address: the bridge is attached later),
	// or ":<port>", bound on every address.
	Listen string `json:"listen"`
	// To is the backend, host:port. A name is looked up per connection, so
	// a container name on the internal network works.
	To string `json:"to"`
	// Once closes the listener after its first connection: the VNC side,
	// which guacd connects to once per session.
	Once bool `json:"once,omitempty"`
	// Retry is how long a failed backend dial is retried for before the
	// client is dropped: the browser's VNC server takes a moment to listen.
	Retry Duration `json:"retry,omitempty"`
}

// Duration is a time.Duration that marshals as its string form.
type Duration time.Duration

// MarshalJSON writes the duration as "15s".
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// UnmarshalJSON reads "15s" or a number of nanoseconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(v)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*d = Duration(n)
	return nil
}

// SOCKS is how the browser reaches an application's origins (ADR 0037,
// amended 2026-11-02): a SOCKS5 listener on the session network that takes
// CONNECT for exactly the host:port pairs in Allow and dials, for each, the
// address the gateway resolved under the address rules. The browser names
// the host it wants and never resolves one; the relay never resolves one
// either, so a name means what the gateway checked when the session began.
type SOCKS struct {
	// Listen is "internal:<port>": the session network only, never the
	// bridge, where it would let any container there reach the origins.
	Listen string  `json:"listen"`
	Allow  []Route `json:"allow"`
}

// Route is one origin's host and port as the browser asks for them, and the
// address that answers.
type Route struct {
	// Host is a hostname or an IP literal, compared without case, a
	// trailing dot or brackets.
	Host string `json:"host"`
	Port int    `json:"port"`
	// To is ip:port, the pinned answer; never a name.
	To string `json:"to"`
}

// Config is the relay's whole table.
type Config struct {
	Forwards []Forward `json:"forwards"`
	// SOCKS, when set, is the browser's way to the application's origins.
	SOCKS *SOCKS `json:"socks,omitempty"`
	// InternalSubnet is the session network's subnet, CIDR; an "internal:"
	// listen binds the relay's address inside it. The gateway attaches the
	// relay to the bridge right after starting it, so by the time the relay
	// looks the relay may have two addresses, and the subnet says which.
	// Empty, the relay expects exactly one address.
	InternalSubnet string `json:"internal_subnet,omitempty"`
}

// Parse decodes and validates a configuration document.
func Parse(raw []byte) (Config, error) {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("apprelay config: %w", err)
	}
	return c, c.Validate()
}

// Validate refuses an empty table, a listen that is not a port, and a
// backend that is not host:port; for SOCKS, a listen off the session
// network or shared with a forward, and a route that repeats another or
// whose answer is a name.
func (c *Config) Validate() error {
	if len(c.Forwards) == 0 && c.SOCKS == nil {
		return errors.New("apprelay config: no forwards")
	}
	if err := c.validSOCKS(); err != nil {
		return err
	}
	if c.InternalSubnet != "" {
		if _, _, err := net.ParseCIDR(c.InternalSubnet); err != nil {
			return fmt.Errorf("apprelay config: internal_subnet: %w", err)
		}
	}
	for i := range c.Forwards {
		f := &c.Forwards[i]
		if _, err := listenPort(f.Listen); err != nil {
			return fmt.Errorf("apprelay config: forward %d: %w", i, err)
		}
		host, port, err := net.SplitHostPort(f.To)
		if err != nil || host == "" {
			return fmt.Errorf("apprelay config: forward %d: to must be host:port", i)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("apprelay config: forward %d: to has no valid port", i)
		}
		if f.Retry < 0 {
			return fmt.Errorf("apprelay config: forward %d: retry is negative", i)
		}
	}
	return nil
}

// listenPort reads the port of a listen spec, "internal:<port>" or ":<port>".
func listenPort(listen string) (int, error) {
	var port string
	switch {
	case strings.HasPrefix(listen, "internal:"):
		port = strings.TrimPrefix(listen, "internal:")
	case strings.HasPrefix(listen, ":"):
		port = strings.TrimPrefix(listen, ":")
	default:
		return 0, errors.New(`listen must be "internal:<port>" or ":<port>"`)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("listen has no valid port")
	}
	return n, nil
}

// validSOCKS checks the SOCKS section, when there is one.
func (c *Config) validSOCKS() error {
	s := c.SOCKS
	if s == nil {
		return nil
	}
	if !strings.HasPrefix(s.Listen, "internal:") {
		return errors.New(`apprelay config: socks listen must be "internal:<port>"`)
	}
	port, err := listenPort(s.Listen)
	if err != nil {
		return fmt.Errorf("apprelay config: socks: %w", err)
	}
	for _, f := range c.Forwards {
		if p, _ := listenPort(f.Listen); p == port {
			return fmt.Errorf("apprelay config: socks listens on %d, as a forward does", port)
		}
	}
	if len(s.Allow) == 0 {
		return errors.New("apprelay config: socks allows nothing")
	}
	seen := map[string]bool{}
	for i, rt := range s.Allow {
		host := normHost(rt.Host)
		if host == "" || rt.Port < 1 || rt.Port > 65535 {
			return fmt.Errorf("apprelay config: socks route %d: host and a port 1-65535 are required", i)
		}
		key := net.JoinHostPort(host, strconv.Itoa(rt.Port))
		if seen[key] {
			return fmt.Errorf("apprelay config: socks route %d repeats %s", i, key)
		}
		seen[key] = true
		ip, p, err := net.SplitHostPort(rt.To)
		if err != nil || net.ParseIP(ip) == nil {
			return fmt.Errorf("apprelay config: socks route %d: to must be ip:port, never a name", i)
		}
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("apprelay config: socks route %d: to has no valid port", i)
		}
	}
	return nil
}

// normHost is a host as routes compare it: lowercase, without a trailing
// dot or IPv6 brackets, and an IP literal in its canonical form, so the
// browser's "APP.corp." and "[FD00::1]" find "app.corp" and "fd00::1".
func normHost(h string) string {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	return h
}

// Relay runs a Config.
type Relay struct {
	Config Config
	Log    *slog.Logger
	// InternalIP is the address "internal:" listens bind to; empty finds
	// the relay's one non-loopback IPv4 address at Serve.
	InternalIP string
	// Dial is the backend dialer; nil uses net.Dialer with a 5 s timeout.
	Dial func(ctx context.Context, addr string) (net.Conn, error)
	// HandshakeTimeout bounds a SOCKS client's greeting and request; zero is
	// 10 s.
	HandshakeTimeout time.Duration
}

// Serve listens for every forward and pumps connections until ctx ends or
// every once-listener has had its connection and closed.
func (r *Relay) Serve(ctx context.Context) error {
	if r.Log == nil {
		r.Log = slog.Default()
	}
	if r.Dial == nil {
		d := &net.Dialer{Timeout: 5 * time.Second}
		r.Dial = func(ctx context.Context, addr string) (net.Conn, error) { return d.DialContext(ctx, "tcp", addr) }
	}
	var internal string
	needInternal := r.Config.SOCKS != nil
	for _, f := range r.Config.Forwards {
		needInternal = needInternal || strings.HasPrefix(f.Listen, "internal:")
	}
	if needInternal {
		ip, err := r.internalIP()
		if err != nil {
			return err
		}
		internal = ip
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	errc := make(chan error, len(r.Config.Forwards)+1)
	lc := &net.ListenConfig{}
	for _, f := range r.Config.Forwards {
		port, _ := listenPort(f.Listen)
		addr := net.JoinHostPort("", strconv.Itoa(port))
		if strings.HasPrefix(f.Listen, "internal:") {
			addr = net.JoinHostPort(internal, strconv.Itoa(port))
		}
		ln, err := lc.Listen(ctx, "tcp", addr)
		if err != nil {
			cancel()
			wg.Wait()
			return fmt.Errorf("apprelay: listen %s: %w", addr, err)
		}
		r.Log.Info("apprelay listening", "addr", ln.Addr().String(), "to", f.To, "once", f.Once)
		wg.Add(1)
		go func(f Forward, ln net.Listener) {
			defer wg.Done()
			errc <- r.serveOne(ctx, f, ln)
		}(f, ln)
	}
	if s := r.Config.SOCKS; s != nil {
		port, _ := listenPort(s.Listen)
		addr := net.JoinHostPort(internal, strconv.Itoa(port))
		ln, err := lc.Listen(ctx, "tcp", addr)
		if err != nil {
			cancel()
			wg.Wait()
			return fmt.Errorf("apprelay: listen %s: %w", addr, err)
		}
		r.Log.Info("apprelay socks listening", "addr", ln.Addr().String(), "routes", len(s.Allow))
		wg.Add(1)
		go func() {
			defer wg.Done()
			errc <- r.serveSOCKS(ctx, s, ln)
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	}
	return nil
}

// serveOne accepts on ln for one forward. A once-forward closes the
// listener after its first connection and returns when that connection ends.
func (r *Relay) serveOne(ctx context.Context, f Forward, ln net.Listener) error {
	defer func() { _ = ln.Close() }()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if f.Once {
			// One connection, and nobody else's: the listener goes before
			// the pump starts, so a second connect is refused at the socket.
			_ = ln.Close()
			r.pump(ctx, f, c)
			return nil
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.pump(ctx, f, c)
		}()
	}
}

// pump dials the backend, retrying within f.Retry, and copies both ways
// until either side closes or ctx ends.
func (r *Relay) pump(ctx context.Context, f Forward, c net.Conn) {
	defer func() { _ = c.Close() }()
	b, err := r.dialBackend(ctx, f)
	if err != nil {
		r.Log.Warn("apprelay backend unreachable", "to", f.To, "err", err)
		return
	}
	defer func() { _ = b.Close() }()
	pipe(ctx, c, b)
}

// pipe copies c and b both ways until either side closes or ctx ends.
func pipe(ctx context.Context, c, b net.Conn) {
	done := make(chan struct{}, 2)
	half := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}
	go half(b, c)
	go half(c, b)
	// Each direction ends on its own, with a half-close passed on, so a
	// backend may still answer after the client has said all it will; the
	// session's end closes both at once.
	for pending := 2; pending > 0; {
		select {
		case <-done:
			pending--
		case <-ctx.Done():
			_ = c.Close()
			_ = b.Close()
			<-done
			if pending == 2 {
				<-done
			}
			return
		}
	}
}

// dialBackend dials f.To, retrying every 250 ms for f.Retry.
func (r *Relay) dialBackend(ctx context.Context, f Forward) (net.Conn, error) {
	deadline := time.Now().Add(time.Duration(f.Retry))
	for {
		b, err := r.Dial(ctx, f.To)
		if err == nil {
			return b, nil
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// internalIP is the relay's address on the session network: the one inside
// InternalSubnet, or, with no subnet given, its one non-loopback IPv4
// address.
func (r *Relay) internalIP() (string, error) {
	if r.InternalIP != "" {
		return r.InternalIP, nil
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	var subnet *net.IPNet
	if r.Config.InternalSubnet != "" {
		if _, subnet, err = net.ParseCIDR(r.Config.InternalSubnet); err != nil {
			return "", err
		}
	}
	var found []string
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.To4() == nil {
			continue
		}
		if subnet != nil {
			if subnet.Contains(ipn.IP) {
				return ipn.IP.String(), nil
			}
			continue
		}
		found = append(found, ipn.IP.String())
	}
	if subnet != nil {
		return "", fmt.Errorf("apprelay: no address inside %s to bind the internal forward to", r.Config.InternalSubnet)
	}
	if len(found) != 1 {
		return "", fmt.Errorf("apprelay: expected one address to bind the internal forward to, found %d (%s)", len(found), strings.Join(found, ", "))
	}
	return found[0], nil
}
