// SPDX-License-Identifier: Apache-2.0

package apprelay

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// socksClient is the browser's side, written out byte by byte so each case
// can say exactly what it sends: the greeting with methods, then a request
// with cmd, an address type and the host and port. It returns the reply code
// and, on success, the connection to talk through.
func socksClient(t *testing.T, addr string, methods []byte, cmd, atyp byte, host string, port int) (byte, net.Conn) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		t.Fatal(err)
	}
	var choice [2]byte
	if _, err := io.ReadFull(c, choice[:]); err != nil {
		t.Fatalf("method choice: %v", err)
	}
	if choice[1] != 0 {
		_ = c.Close()
		return choice[1], nil
	}
	req := []byte{5, cmd, 0, atyp}
	switch atyp {
	case atypDomain:
		req = append(append(req, byte(len(host))), host...)
	case atypIPv4:
		req = append(req, net.ParseIP(host).To4()...)
	case atypIPv6:
		req = append(req, net.ParseIP(host).To16()...)
	default:
		req = append(req, 0, 0, 0, 0)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if reply[1] != replySucceeded {
		_ = c.Close()
		return reply[1], nil
	}
	_ = c.SetDeadline(time.Time{})
	t.Cleanup(func() { _ = c.Close() })
	return reply[1], c
}

// socksRelay serves a relay whose SOCKS routes app.corp:443, the IP literal
// 10.9.9.9:8080 and the IPv6 literal fd00::9:443 to one echo backend.
func socksRelay(t *testing.T) string {
	t.Helper()
	be := echoBackend(t).Addr().String()
	port := freePort(t)
	serve(t, Config{SOCKS: &SOCKS{Listen: "internal:" + strconv.Itoa(port), Allow: []Route{
		{Host: "app.corp", Port: 443, To: be},
		{Host: "10.9.9.9", Port: 8080, To: be},
		{Host: "[FD00::9]", Port: 443, To: be},
	}}})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	waitListening(t, addr)
	return addr
}

func echoes(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
		t.Fatalf("through the relay: %q %v, want %q", buf, err, msg)
	}
}

// TestSOCKSConnectsAllowedOrigins: the browser reaches each allowed origin by
// the name it asks for, in whatever case and with a trailing dot, and an IP
// literal origin by address or, as Chromium sends it, by the literal as a
// name; the bytes go through to the pinned address and back.
func TestSOCKSConnectsAllowedOrigins(t *testing.T) {
	addr := socksRelay(t)
	for _, c := range []struct {
		atyp byte
		host string
		port int
	}{
		{atypDomain, "app.corp", 443},
		{atypDomain, "APP.Corp.", 443},
		{atypIPv4, "10.9.9.9", 8080},
		{atypDomain, "10.9.9.9", 8080},
		{atypIPv6, "fd00::9", 443},
		{atypDomain, "[fd00::9]", 443},
	} {
		code, conn := socksClient(t, addr, []byte{0}, socksConnect, c.atyp, c.host, c.port)
		if code != replySucceeded {
			t.Errorf("%s:%d (atyp %d): reply %d, want success", c.host, c.port, c.atyp, code)
			continue
		}
		echoes(t, conn, "hello "+c.host)
	}
}

// TestSOCKSRefusesEverythingElse: a host that is not an origin, an origin's
// host on another port, and a name that merely ends like an origin's are
// refused with "not allowed by ruleset", whatever the backend could reach.
func TestSOCKSRefusesEverythingElse(t *testing.T) {
	addr := socksRelay(t)
	for _, c := range []struct {
		atyp byte
		host string
		port int
	}{
		{atypDomain, "evil.corp", 443},
		{atypDomain, "app.corp", 8443},
		{atypDomain, "x.app.corp", 443},
		{atypDomain, "app.corp.evil", 443},
		{atypIPv4, "10.9.9.9", 443},
		{atypIPv4, "169.254.169.254", 80},
		{atypDomain, "localhost", 443},
	} {
		if code, _ := socksClient(t, addr, []byte{0}, socksConnect, c.atyp, c.host, c.port); code != replyNotAllowed {
			t.Errorf("%s:%d: reply %d, want %d (not allowed)", c.host, c.port, code, replyNotAllowed)
		}
	}
}

// TestSOCKSSpeaksOnlyConnectWithoutAuth: BIND and UDP ASSOCIATE are answered
// "command not supported", an unknown address type "not supported", and a
// client offering no unauthenticated method is told none is acceptable.
func TestSOCKSSpeaksOnlyConnectWithoutAuth(t *testing.T) {
	addr := socksRelay(t)
	for _, cmd := range []byte{2, 3} {
		if code, _ := socksClient(t, addr, []byte{0}, cmd, atypDomain, "app.corp", 443); code != replyCmdUnsupported {
			t.Errorf("cmd %d: reply %d, want %d", cmd, code, replyCmdUnsupported)
		}
	}
	if code, _ := socksClient(t, addr, []byte{0}, socksConnect, 9, "", 443); code != replyAtypUnsupported {
		t.Errorf("address type 9: reply %d, want %d", code, replyAtypUnsupported)
	}
	if code, _ := socksClient(t, addr, []byte{2}, socksConnect, atypDomain, "app.corp", 443); code != socksNoMethods {
		t.Errorf("username/password only: method %d, want %d", code, socksNoMethods)
	}
}

// TestSOCKSDropsBadAndSilentClients: a client speaking another version is
// dropped without an answer, and one that says nothing is dropped when the
// handshake's time runs out rather than holding a connection for ever.
func TestSOCKSDropsBadAndSilentClients(t *testing.T) {
	be := echoBackend(t).Addr().String()
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := &Relay{Config: Config{SOCKS: &SOCKS{Listen: "internal:" + strconv.Itoa(port), Allow: []Route{{Host: "app.corp", Port: 443, To: be}}}},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), InternalIP: "127.0.0.1", HandshakeTimeout: 200 * time.Millisecond}
	go func() { _ = r.Serve(ctx) }()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	waitListening(t, addr)

	// Dropped is the relay ending the connection: an EOF, or a reset when it
	// closed with the client's bytes unread; a timeout means it held on.
	closed := func(c net.Conn, within time.Duration) bool {
		_ = c.SetReadDeadline(time.Now().Add(within))
		_, err := c.Read(make([]byte, 1))
		var ne net.Error
		return err != nil && (!errors.As(err, &ne) || !ne.Timeout())
	}
	v4, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = v4.Close() }()
	_, _ = v4.Write([]byte{4, 1, 0, 80, 10, 0, 0, 1, 0})
	if !closed(v4, 2*time.Second) {
		t.Fatal("a SOCKS4 client was not dropped")
	}
	silent, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()
	if !closed(silent, 2*time.Second) {
		t.Fatal("a silent client outlived the handshake deadline")
	}
}

// TestSOCKSSaysWhenTheOriginIsDown: an allowed origin with nothing listening
// is answered "connection refused", so the browser shows its own error page
// for the origin rather than hanging.
func TestSOCKSSaysWhenTheOriginIsDown(t *testing.T) {
	down := net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))
	port := freePort(t)
	serve(t, Config{SOCKS: &SOCKS{Listen: "internal:" + strconv.Itoa(port), Allow: []Route{{Host: "app.corp", Port: 443, To: down}}}})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	waitListening(t, addr)
	if code, _ := socksClient(t, addr, []byte{0}, socksConnect, atypDomain, "app.corp", 443); code != replyRefused {
		t.Fatalf("reply %d, want %d (refused)", code, replyRefused)
	}
}

// TestSOCKSConfigRefuses: the SOCKS section is checked before anything
// listens: only on the session network, never on a forward's port, at least
// one route, no route twice (as hosts compare), and answers that are
// addresses, never names a lookup could change.
func TestSOCKSConfigRefuses(t *testing.T) {
	ok := Route{Host: "app.corp", Port: 443, To: "10.0.0.5:443"}
	for _, c := range []struct {
		name, wantIn string
		cfg          Config
	}{
		{"every address", "must be \"internal:<port>\"", Config{SOCKS: &SOCKS{Listen: ":1080", Allow: []Route{ok}}}},
		{"a forward's port", "as a forward does", Config{
			Forwards: []Forward{{Listen: "internal:1080", To: "10.0.0.5:1080"}},
			SOCKS:    &SOCKS{Listen: "internal:1080", Allow: []Route{ok}}}},
		{"no routes", "allows nothing", Config{SOCKS: &SOCKS{Listen: "internal:1080"}}},
		{"a repeat", "repeats app.corp:443", Config{SOCKS: &SOCKS{Listen: "internal:1080", Allow: []Route{ok, {Host: "APP.corp.", Port: 443, To: "10.0.0.6:443"}}}}},
		{"a name for an answer", "never a name", Config{SOCKS: &SOCKS{Listen: "internal:1080", Allow: []Route{{Host: "app.corp", Port: 443, To: "app.corp:443"}}}}},
		{"no port", "port 1-65535", Config{SOCKS: &SOCKS{Listen: "internal:1080", Allow: []Route{{Host: "app.corp", To: "10.0.0.5:443"}}}}},
		{"no host", "host and a port", Config{SOCKS: &SOCKS{Listen: "internal:1080", Allow: []Route{{Port: 443, To: "10.0.0.5:443"}}}}},
	} {
		err := c.cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), c.wantIn) {
			t.Errorf("%s: %v, want an error containing %q", c.name, err, c.wantIn)
		}
	}
	if err := (&Config{SOCKS: &SOCKS{Listen: "internal:1080", Allow: []Route{ok}}}).Validate(); err != nil {
		t.Fatalf("a SOCKS-only table is valid: %v", err)
	}
}
