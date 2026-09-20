// SPDX-License-Identifier: Apache-2.0

// Command zanskar is the single binary for the Zanskar access gateway.
//
//	zanskar serve     run the gateway
//	zanskar migrate   apply pending database migrations and exit
//	zanskar keygen    print a new base64 master key for ZANSKAR_MASTER_KEY
//	zanskar audit verify   walk the audit log and check the hash chain
//	zanskar version   print the build version
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/connect"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/group"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/server"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/ticket"
	"github.com/albatroxxx/zanskar/internal/user"
	"github.com/albatroxxx/zanskar/internal/user/adminapi"
	"github.com/albatroxxx/zanskar/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe()
	case "migrate":
		err = runMigrate()
	case "keygen":
		err = runKeygen()
	case "version":
		fmt.Println(version.Version)
	case "admin":
		err = runAdmin(os.Args[2:])
	case "audit":
		err = runAudit(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: zanskar <serve|migrate|keygen|admin create|audit verify|version>")
}

func newLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	_ = level.UnmarshalText([]byte(cfg.LogLevel))
	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}

func runServe() error {
	cfg, err := config.Load(config.Options{RequireMasterKey: true})
	if err != nil {
		return err
	}
	log := newLogger(cfg)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	pending, err := store.Pending(ctx, db)
	if err != nil {
		return err
	}
	if len(pending) > 0 {
		// Migrations are an explicit operator action, never a side effect of start.
		return fmt.Errorf("%d migration(s) pending; run `zanskar migrate` first", len(pending))
	}

	kek, err := crypto.NewLocalKEK(cfg.MasterKey)
	if err != nil {
		return err
	}
	ring, err := keyring.Open(ctx, db, kek)
	if err != nil {
		return fmt.Errorf("key ring: %w", err)
	}
	defer ring.Close()

	csrfKey, err := crypto.DeriveKey(cfg.MasterKey, "zanskar/csrf")
	if err != nil {
		return err
	}
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, csrfKey, cfg.SecureCookies())
	if !cfg.SecureCookies() {
		log.Warn("session cookies are not marked Secure; fine on loopback, never in production")
	}
	auditLog := audit.NewLog(db)
	totp := auth.NewTOTP(db, ring, cfg.Issuer)
	authHandler := auth.NewHandler(users, sessions, totp, auditLog, log)
	authHandler.RequireMFA = cfg.RequireMFA
	if !cfg.RequireMFA {
		log.Warn("ZANSKAR_REQUIRE_MFA=false: password-only logins are allowed")
	}
	vault := credential.NewVault(db, ring)
	targets := target.NewRepo(db)
	policies := policy.NewRepo(db)
	sessionRepo := session.NewRepo(db)
	registry := gateway.NewRegistry()
	storage := &recording.LocalStorage{Dir: cfg.RecordingsDir}
	deps := server.Deps{
		AuthMiddleware: &auth.Middleware{Sessions: sessions, Users: users, Log: log},
		Auth:           authHandler,
		Handlers: []server.Registrar{
			&adminapi.AdminHandler{Users: users, Sessions: sessions, TOTP: totp, Audit: auditLog, Log: log},
			&group.AdminHandler{Groups: group.NewRepo(db), Audit: auditLog, Log: log},
			&credential.AdminHandler{Vault: vault, Audit: auditLog, Log: log},
			&target.AdminHandler{Repo: targets, Prober: &target.Prober{}, Audit: auditLog, Log: log},
			&policy.AdminHandler{Repo: policies, Audit: auditLog, Log: log},
			&session.Handler{Repo: sessionRepo, Audit: auditLog, Registry: registry, Storage: storage, Log: log},
			&connect.Handler{Targets: targets, Policies: policies, Vault: vault, Sessions: sessionRepo, Tickets: ticket.NewStore(),
				Registry: registry, Storage: storage, Audit: auditLog, Log: log, MFAEnrolled: totp.Enrolled},
		},
	}
	if n, err := users.CountAdmins(ctx); err == nil && n == 0 {
		log.Warn("no admin user exists; create one with `zanskar admin create`")
	}

	log.Info("starting zanskar", "version", version.Version, "db_driver", cfg.DBDriver, "key_version", ring.ActiveVersion())
	return server.New(cfg, db, log, deps).ListenAndServe(ctx)
}

func runMigrate() error {
	cfg, err := config.Load(config.Options{})
	if err != nil {
		return err
	}
	log := newLogger(cfg)
	ctx := context.Background()
	db, err := store.Open(ctx, cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	ran, err := store.Migrate(ctx, db)
	if err != nil {
		return err
	}
	log.Info("migrations applied", "count", len(ran), "versions", ran)
	return nil
}

func runKeygen() error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(key))
	return nil
}
