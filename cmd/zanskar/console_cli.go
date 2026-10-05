// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log/slog"
	"net/http"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/cli"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/server"
)

// consoleCLI returns the console's command line (ADR 0027), or nothing when
// ZANSKAR_CONSOLE_CLI=off: its routes then do not exist, and the console,
// seeing them answer 404, does not show the button.
func consoleCLI(cfg *config.Config, sessions *auth.Sessions, totp *auth.TOTP, auditLog *audit.Log, log *slog.Logger) server.Registrar {
	if !cfg.ConsoleCLI {
		log.Info("console command line is off (ZANSKAR_CONSOLE_CLI=off)")
		return noRoutes{}
	}
	return &cli.Handler{Sessions: sessions, MFA: totp, Audit: auditLog, Log: log}
}

type noRoutes struct{}

func (noRoutes) Register(*http.ServeMux) {}
