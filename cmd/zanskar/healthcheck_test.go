// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// readyServer stands in for the gateway's listener: /readyz answers status,
// and every path asked for is kept.
type readyServer struct {
	mu    sync.Mutex
	paths []string
}

func (s *readyServer) handler(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.paths = append(s.paths, r.URL.Path)
		s.mu.Unlock()
		if r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		if status == http.StatusFound {
			http.Redirect(w, r, "/healthz", status)
			return
		}
		w.WriteHeader(status)
	})
}

// healthcheck runs `zanskar healthcheck` against listen with the given TLS
// mode and returns the exit code and what it printed on stderr.
func healthcheck(t *testing.T, listen, tlsMode string) (int, string) {
	t.Helper()
	t.Setenv("ZANSKAR_LISTEN_ADDR", listen)
	t.Setenv("ZANSKAR_TLS_MODE", tlsMode)
	t.Setenv("ZANSKAR_TLS_CERT", "")
	t.Setenv("ZANSKAR_TLS_KEY", "")
	var code int
	_, stderr, _ := output(t, func() error { code = run([]string{"healthcheck"}); return nil })
	return code, stderr
}

// TestHealthcheck: the image has no shell, curl or wget, so a container
// runtime asks the binary itself whether the gateway is ready. It gets
// /readyz from where serve listens (loopback for a wildcard address, https
// when the gateway serves TLS, the certificate being its own and possibly
// self-signed), exits 0 on 200 and 1 otherwise, saying why. A redirect is
// not followed: the answer must be the listener's own.
func TestHealthcheck(t *testing.T) {
	s := &readyServer{}
	ready := httptest.NewServer(s.handler(http.StatusOK))
	defer ready.Close()
	addr := ready.Listener.Addr().String()
	if code, stderr := healthcheck(t, addr, ""); code != 0 {
		t.Fatalf("ready gateway: exit %d, want 0: %s", code, stderr)
	}
	if strings.Join(s.paths, ",") != "/readyz" {
		t.Fatalf("asked for %v, want /readyz once", s.paths)
	}
	_, port, _ := net.SplitHostPort(addr)
	if code, stderr := healthcheck(t, "0.0.0.0:"+port, ""); code != 0 {
		t.Fatalf("wildcard listen address: exit %d, want 0 (probed on loopback): %s", code, stderr)
	}

	notReady := httptest.NewServer((&readyServer{}).handler(http.StatusServiceUnavailable))
	defer notReady.Close()
	if code, stderr := healthcheck(t, notReady.Listener.Addr().String(), ""); code != 1 || !strings.Contains(stderr, "503") {
		t.Fatalf("gateway not ready: exit %d, stderr %q; want 1 naming 503", code, stderr)
	}
	redirect := httptest.NewServer((&readyServer{}).handler(http.StatusFound))
	defer redirect.Close()
	if code, stderr := healthcheck(t, redirect.Listener.Addr().String(), ""); code != 1 || !strings.Contains(stderr, "302") {
		t.Fatalf("a redirect: exit %d, stderr %q; want 1 naming 302", code, stderr)
	}
	if code, stderr := healthcheck(t, freeAddr(t), ""); code != 1 || !strings.Contains(stderr, "healthcheck") {
		t.Fatalf("nothing listening: exit %d, stderr %q; want 1", code, stderr)
	}

	tlsReady := httptest.NewTLSServer((&readyServer{}).handler(http.StatusOK))
	defer tlsReady.Close()
	for _, mode := range []string{"managed", "file"} {
		if code, stderr := healthcheck(t, tlsReady.Listener.Addr().String(), mode); code != 0 {
			t.Fatalf("TLS mode %s: exit %d, want 0: %s", mode, code, stderr)
		}
	}
	if code, _ := healthcheck(t, tlsReady.Listener.Addr().String(), "proxy"); code != 1 {
		t.Fatalf("plain HTTP to a TLS listener: exit %d, want 1", code)
	}
	if code, stderr := healthcheck(t, "no-port", ""); code != 1 || !strings.Contains(stderr, "ZANSKAR_LISTEN_ADDR") {
		t.Fatalf("a listen address without a port: exit %d, stderr %q", code, stderr)
	}
}
