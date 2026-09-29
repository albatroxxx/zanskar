// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/albatroxxx/zanskar/internal/gateway/mysqlrelay"
)

// runDBProxy is the MySQL/MariaDB relay sidecar (ADR 0017): the gateway
// starts its own image with this command beside each database session. The
// configuration, credential included, arrives as one JSON document in
// ZANSKAR_DBPROXY, never in argv. It serves until the gateway removes the
// container at the end of the session.
func runDBProxy() error {
	raw := os.Getenv("ZANSKAR_DBPROXY")
	if raw == "" {
		return errors.New("dbproxy: ZANSKAR_DBPROXY is not set; this command is started by the gateway for a database session")
	}
	// The variable has been read; drop it from this process's environment so
	// a diagnostic dump of it cannot show the credential.
	_ = os.Unsetenv("ZANSKAR_DBPROXY")
	cfg, err := mysqlrelay.Parse([]byte(raw))
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.Info("dbproxy listening", "addr", ln.Addr().String(), "user", cfg.User, "upstream_tls", string(cfg.Upstream.TLS))
	return (&mysqlrelay.Relay{Config: cfg, Log: log}).Serve(ctx, ln)
}
