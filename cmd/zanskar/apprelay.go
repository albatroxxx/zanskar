// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/albatroxxx/zanskar/internal/gateway/apprelay"
)

// runAppRelay is the relay beside an application session (ADR 0034): the
// gateway starts its own image with this command on the session's internal
// network. The forwarding table arrives as one JSON document in
// ZANSKAR_APPRELAY, never in argv. It serves until the gateway removes the
// container at the end of the session.
func runAppRelay() error {
	raw := os.Getenv("ZANSKAR_APPRELAY")
	if raw == "" {
		return errors.New("apprelay: ZANSKAR_APPRELAY is not set; this command is started by the gateway for an application session")
	}
	_ = os.Unsetenv("ZANSKAR_APPRELAY")
	cfg, err := apprelay.Parse([]byte(raw))
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return (&apprelay.Relay{Config: cfg, Log: log}).Serve(ctx)
}
