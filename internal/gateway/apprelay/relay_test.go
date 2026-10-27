// SPDX-License-Identifier: Apache-2.0

package apprelay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// echoBackend answers every connection by echoing its bytes.
func echoBackend(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func serve(t *testing.T, cfg Config) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &Relay{Config: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), InternalIP: "127.0.0.1"}
	errc := make(chan error, 1)
	go func() { errc <- r.Serve(ctx) }()
	t.Cleanup(cancel)
	return cancel, errc
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	for range 100 {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never listened", addr)
}

func roundTrip(t *testing.T, addr, msg string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read back through %s: %v", addr, err)
	}
	return string(buf)
}

// TestForwardBothWays: bytes go through an "internal:" listener to the
// backend and back, for several connections at once.
func TestForwardBothWays(t *testing.T) {
	be := echoBackend(t)
	port := freePort(t)
	serve(t, Config{Forwards: []Forward{{Listen: "internal:" + strconv.Itoa(port), To: be.Addr().String()}}})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	waitListening(t, addr)
	var wg sync.WaitGroup
	for i := range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg := strings.Repeat("x", 1000) + strconv.Itoa(i)
			if got := roundTrip(t, addr, msg); got != msg {
				t.Errorf("connection %d: got %d bytes back, wrong content", i, len(got))
			}
		}()
	}
	wg.Wait()
}

// TestOnceTakesOneConnection: a once-forward serves its first connection
// and refuses a second at the socket, and Serve returns once that one ends.
func TestOnceTakesOneConnection(t *testing.T) {
	be := echoBackend(t)
	port := freePort(t)
	_, errc := serve(t, Config{Forwards: []Forward{{Listen: ":" + strconv.Itoa(port), To: be.Addr().String(), Once: true}}})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	waitListening(t, addr)
	// waitListening consumed the one connection; the listener is closed now.
	time.Sleep(50 * time.Millisecond)
	if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatal("a second connection was accepted on a once-forward")
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("serve after the one connection: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after the once-forward's connection ended")
	}
}

// TestRetryWaitsForBackend: a backend that starts listening after the client
// connected is reached within Retry; without Retry the client is dropped.
func TestRetryWaitsForBackend(t *testing.T) {
	bePort := freePort(t)
	beAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(bePort))
	port := freePort(t)
	serve(t, Config{Forwards: []Forward{{Listen: ":" + strconv.Itoa(port), To: beAddr, Retry: Duration(5 * time.Second)}}})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	waitListening(t, addr)
	go func() {
		time.Sleep(600 * time.Millisecond)
		ln, err := net.Listen("tcp", beAddr)
		if err != nil {
			return
		}
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(c, c)
		_ = c.Close()
		_ = ln.Close()
	}()
	if got := roundTrip(t, addr, "late"); got != "late" {
		t.Fatalf("through a late backend: %q", got)
	}

	// No retry, no backend: the client is closed without data.
	port2 := freePort(t)
	serve(t, Config{Forwards: []Forward{{Listen: ":" + strconv.Itoa(port2), To: net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))}}})
	addr2 := net.JoinHostPort("127.0.0.1", strconv.Itoa(port2))
	waitListening(t, addr2)
	c, err := net.DialTimeout("tcp", addr2, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := c.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("a dead backend's client: n=%d err=%v, want EOF", n, err)
	}
}

// TestParseRefuses: the table must be non-empty, listens must be ports,
// backends host:port.
func TestParseRefuses(t *testing.T) {
	for _, bad := range []string{
		`{}`,
		`{"forwards":[]}`,
		`{"forwards":[{"listen":"80","to":"10.0.0.1:80"}]}`,
		`{"forwards":[{"listen":"internal:0","to":"10.0.0.1:80"}]}`,
		`{"forwards":[{"listen":":80","to":"10.0.0.1"}]}`,
		`{"forwards":[{"listen":":80","to":":80"}]}`,
		`{"forwards":[{"listen":":80","to":"10.0.0.1:99999"}]}`,
		`{"forwards":[{"listen":":80","to":"10.0.0.1:80","retry":"-1s"}]}`,
		`not json`,
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	c, err := Parse([]byte(`{"forwards":[{"listen":"internal:80","to":"10.0.0.1:80"},{"listen":":5900","to":"browser:5900","once":true,"retry":"15s"}]}`))
	if err != nil || len(c.Forwards) != 2 || !c.Forwards[1].Once || time.Duration(c.Forwards[1].Retry) != 15*time.Second {
		t.Fatalf("good table: %+v %v", c, err)
	}
}

// TestInternalIPNeedsExactlyOne: with no address given, Serve refuses a
// table that binds "internal:" unless the host has exactly one address; the
// test only checks the refusal path through an explicit empty list.
func TestInternalIPNeedsExactlyOne(t *testing.T) {
	r := &Relay{Config: Config{Forwards: []Forward{{Listen: "internal:80", To: "10.0.0.1:80"}}}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ip, err := r.internalIP()
	addrs, _ := net.InterfaceAddrs()
	n := 0
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
			n++
		}
	}
	if (n == 1) != (err == nil) {
		t.Fatalf("host has %d addresses, internalIP gave %q %v", n, ip, err)
	}
}
