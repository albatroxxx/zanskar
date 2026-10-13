// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
)

// healthcheckTimeout bounds the whole probe, under the five seconds the
// shipped compose file gives a health check.
const healthcheckTimeout = 3 * time.Second

// runHealthcheck asks the gateway running beside it whether it is ready, for
// a container runtime's health check: the image is distroless, with no shell,
// curl or wget, so the binary asks itself. It reads only where serve listens
// and whether it serves TLS (never the master key or the database) and gets
// /readyz there: 200 means the gateway answers and its database is reachable
// with no migration pending. It exits 0 when ready and 1 otherwise.
func runHealthcheck() error {
	addr, servesTLS := config.Listener()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("healthcheck: ZANSKAR_LISTEN_ADDR %q: %w", addr, err)
	}
	// A gateway listening on every address is asked on loopback, which is in
	// its own container or on its own host.
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	scheme := "http"
	if servesTLS {
		scheme = "https"
	}
	url := scheme + "://" + net.JoinHostPort(host, port) + "/readyz"
	client := &http.Client{
		// The answer must be the listener's own, not a page it points to.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		// No proxy from the environment stands in for the gateway. Its
		// certificate is not checked: the probe sends nothing and reads only
		// the status, and the certificate is often the gateway's self-signed
		// one, made for names other than the address asked here.
		Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, // #nosec G402 -- a readiness probe of the gateway's own listener; nothing is sent, only the status is read
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthcheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: %s answered %s", url, resp.Status)
	}
	return nil
}
