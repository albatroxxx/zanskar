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
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/albatroxxx/zanskar/internal/access"
	"github.com/albatroxxx/zanskar/internal/asg"
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/cloud"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/connect"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/group"
	"github.com/albatroxxx/zanskar/internal/idp"
	idpadmin "github.com/albatroxxx/zanskar/internal/idp/adminapi"
	"github.com/albatroxxx/zanskar/internal/idp/ldap"
	"github.com/albatroxxx/zanskar/internal/idp/oidc"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/lifecycle"
	"github.com/albatroxxx/zanskar/internal/logring"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/recstorage"
	"github.com/albatroxxx/zanskar/internal/server"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/settings"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/ticket"
	"github.com/albatroxxx/zanskar/internal/tlscert"
	"github.com/albatroxxx/zanskar/internal/user"
	"github.com/albatroxxx/zanskar/internal/user/adminapi"
	"github.com/albatroxxx/zanskar/internal/version"
	"github.com/albatroxxx/zanskar/web"
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
	case "init":
		err = runInit(os.Args[2:])
	case "backup":
		err = runBackup(os.Args[2:])
	case "restore":
		err = runRestore(os.Args[2:])
	case "keygen":
		err = runKeygen()
	case "key":
		err = runKey(os.Args[2:])
	case "dbproxy":
		err = runDBProxy()
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
	fmt.Fprintln(os.Stderr, "usage: zanskar <init|serve|migrate|backup|restore|keygen|key status|key rotate|key rotate-master|admin create|admin reset-mfa|audit verify|audit reseal|dbproxy|version>")
}

func newLogger(cfg *config.Config) *slog.Logger {
	log, _, _ := newLeveledLogger(cfg)
	return log
}

// logRingSize is how many recent log records the console can show.
const logRingSize = 2000

// newLeveledLogger builds the logger with a level that can change while the
// process runs (serve binds it to the log.level runtime setting) and a ring
// of the most recent records for the console's log viewer.
func newLeveledLogger(cfg *config.Config) (*slog.Logger, *slog.LevelVar, *logring.Ring) {
	level := new(slog.LevelVar)
	_ = level.UnmarshalText([]byte(cfg.LogLevel))
	opts := &slog.HandlerOptions{Level: level}
	var base slog.Handler
	if cfg.LogFormat == "text" {
		base = slog.NewTextHandler(os.Stderr, opts)
	} else {
		base = slog.NewJSONHandler(os.Stderr, opts)
	}
	ring := logring.New(logRingSize)
	return slog.New(ring.Wrap(base)), level, ring
}

func runServe() error {
	startedAt := time.Now().UTC()
	// Taken before anything else reads or touches the environment: it is
	// what the environment file is later compared against (ADR 0020).
	startedEnv := lifecycle.SnapshotEnv()
	cfg, err := config.Load(config.Options{RequireMasterKey: true})
	if err != nil {
		return err
	}
	log, logLevel, logs := newLeveledLogger(cfg)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// A console-requested restart cancels this context once live sessions
	// have drained; serve then returns nil and the supervisor starts a fresh
	// process that reads the environment file again.
	ctx, exit := context.WithCancel(ctx)
	defer exit()

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

	// The gateway's own certificate (ADR 0021): uploaded in the console, else
	// the file from the environment, else self-signed at first start.
	var tlsMgr *tlscert.Manager
	if cfg.ServesTLS() {
		tlsMgr = &tlscert.Manager{Repo: tlscert.NewRepo(db, ring), Log: log, Hosts: tlscert.LocalHosts(cfg.ListenAddr)}
		if cfg.TLSCert != "" {
			cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
			if err != nil {
				return fmt.Errorf("ZANSKAR_TLS_CERT/ZANSKAR_TLS_KEY: %w", err)
			}
			tlsMgr.File = &cert
		}
		if err := tlsMgr.Load(ctx); err != nil {
			return fmt.Errorf("tls certificate: %w", err)
		}
		a := tlsMgr.Active()
		log.Info("tls certificate", "source", a.Source, "subject", a.Subject, "hosts", a.Hosts, "not_after", a.NotAfter, "sha256", a.Fingerprint)
	}

	// Runtime settings (ADR 0020): the environment gives install-time values,
	// the console overrides them live. Bind the ones this process applies.
	runtime := settings.NewService(settings.NewRepo(db), settings.EnvValues(), bootSettings(cfg, ring.ActiveVersion()))
	if err := runtime.Load(ctx); err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	applyLevel := func(v string) {
		var lvl slog.Level
		if err := lvl.UnmarshalText([]byte(v)); err == nil {
			logLevel.Set(lvl)
		}
	}
	applyLevel(runtime.String(settings.KeyLogLevel))
	runtime.Subscribe(settings.KeyLogLevel, applyLevel)
	requireMFA := func() bool { return runtime.Bool(settings.KeyRequireMFA) }
	guacdAddr := func() string { return runtime.String(settings.KeyGuacdAddr) }

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
	authHandler.RequireMFA = requireMFA
	if !requireMFA() {
		log.Warn("authenticator not required: password-only logins are allowed (auth.require_mfa)")
	}
	groups := group.NewRepo(db)
	idpRepo := idp.NewRepo(db, ring)
	provisioner := &idp.Provisioner{Users: users, Groups: groups}
	stateKey, err := crypto.DeriveKey(cfg.MasterKey, "zanskar/oidc-state")
	if err != nil {
		return err
	}
	authHandler.ExternalLogin = ldapExternalAuth{ldap.NewLogin(idpRepo, provisioner)}
	vault := credential.NewVault(db, ring)
	targets := target.NewRepo(db)
	policies := policy.NewRepo(db)
	accessReqs := access.NewRepo(db)
	sessionRepo := session.NewRepo(db)
	registry := gateway.NewRegistry()
	restarter := &lifecycle.Controller{Registry: registry, Log: log, Exit: exit}
	drift := &lifecycle.Drift{Path: cfg.EnvFile, Started: startedEnv}
	// Recording storage (QA finding R18): the router hands new recordings to
	// the bucket configured in the console, else the environment's, else the
	// local directory, and reads every recording by its own URI.
	router := &recording.Router{Local: &recording.LocalStorage{Dir: cfg.RecordingsDir}}
	var envStorage *recstorage.Config
	if cfg.RecordingsS3Bucket != "" {
		envStorage = &recstorage.Config{Bucket: cfg.RecordingsS3Bucket, Prefix: cfg.RecordingsS3Prefix, Region: cfg.RecordingsS3Region, Endpoint: cfg.RecordingsS3Endpoint, KMSKeyID: cfg.RecordingsS3KMSKey, Auth: recstorage.AuthRole}
		if err := envStorage.Validate(); err != nil {
			return fmt.Errorf("ZANSKAR_RECORDINGS_S3_*: %w", err)
		}
	}
	storageMgr := &recstorage.Manager{Repo: recstorage.NewRepo(db, ring), Router: router, Sessions: sessionRepo, Env: envStorage, SpoolDir: cfg.RecordingsSpoolDir, Log: log}
	if err := storageMgr.Load(ctx); err != nil {
		return fmt.Errorf("recordings storage: %w", err)
	}
	if a := storageMgr.Active(); a != nil {
		log.Info("recordings storage", "backend", "s3", "source", storageMgr.Source(), "bucket", a.Bucket, "prefix", a.Prefix, "kms", a.KMSKeyID != "")
	} else {
		log.Info("recordings storage", "backend", "local", "dir", cfg.RecordingsDir)
	}
	var storage recording.Storage = router
	asgRepo := asg.NewRepo(db)
	cloudProviders := asg.AWSProviders()
	// The gateway's own AWS identity, for autoscaling trust policies (ADR
	// 0023): detected once in the background so the first admin request does
	// not wait on the instance metadata service.
	awsIdentity := cloud.NewGatewayIdentity(cfg.AWSGatewayPrincipal)
	go func() {
		id := awsIdentity.Get(ctx)
		if id.Principal != "" {
			log.Info("aws gateway identity", "source", id.Source, "principal", id.Principal)
		} else {
			log.Info("aws gateway identity not available; autoscaling trust policies need ZANSKAR_AWS_GATEWAY_PRINCIPAL", "detail", id.Error)
		}
	}()
	syncer := &asg.Syncer{Repo: asgRepo, Providers: cloudProviders, Prober: &target.Prober{}, Registry: registry, Audit: auditLog, Log: log}
	deps := server.Deps{
		TLS:            tlsMgr,
		AuthMiddleware: &auth.Middleware{Sessions: sessions, Users: users, Log: log},
		Auth:           authHandler,
		Handlers: []server.Registrar{
			&adminapi.AdminHandler{Users: users, Sessions: sessions, TOTP: totp, Audit: auditLog, Log: log},
			&group.AdminHandler{Groups: groups, Audit: auditLog, Log: log},
			&idpadmin.AdminHandler{Providers: idpRepo, Audit: auditLog, Log: log, LDAPTester: &ldap.Authenticator{}},
			&oidc.Handler{Providers: idpRepo, Provisioner: provisioner, Sessions: sessions, Audit: auditLog, Log: log, StateKey: stateKey, MFAEnrolled: totp.Enrolled, RequireMFA: requireMFA},
			&credential.AdminHandler{Vault: vault, Audit: auditLog, Log: log},
			&target.AdminHandler{Repo: targets, Prober: &target.Prober{}, Policies: policies, Live: registry, Vault: vault, Audit: auditLog, Log: log},
			&policy.AdminHandler{Repo: policies, Users: users, Audit: auditLog, Log: log},
			&access.Handler{Requests: accessReqs, Policies: policies, Targets: targets, Audit: auditLog, Log: log},
			&asg.AdminHandler{Repo: asgRepo, Sync: syncer.SyncGroup, Identity: awsIdentity, Providers: cloudProviders, Policies: policies, Live: registry, Vault: vault, Audit: auditLog, Log: log},
			&session.Handler{Repo: sessionRepo, Audit: auditLog, Registry: registry, Storage: storage, Log: log},
			&settings.Handler{Service: runtime, Audit: auditLog, Log: log},
			&recstorage.Handler{Manager: storageMgr, Audit: auditLog, Log: log},
			&lifecycle.Handler{Drift: drift, Controller: restarter, Audit: auditLog, Log: log, StartedAt: startedAt},
			&logring.API{Ring: logs, Audit: auditLog, Log: log},
			&tlscert.Handler{Manager: tlsMgr, Mode: cfg.TLSMode, Audit: auditLog, Log: log},
			&connect.Handler{Targets: targets, Policies: policies, Access: accessReqs, Vault: vault, Sessions: sessionRepo, Tickets: ticket.NewStore(),
				Registry: registry, Storage: storage, Audit: auditLog, Log: log, MFAEnrolled: totp.Enrolled, GuacdAddr: guacdAddr, Draining: restarter.Draining,
				DockerPath: cfg.DockerPath, DBProxyImage: func() string { return runtime.String(settings.KeyDBProxyImage) },
				Prober: &target.Prober{}, ASGs: asgRepo, Cloud: cloudProviders},
			&connect.ShadowHandler{Registry: registry, Audit: auditLog, Log: log, GuacdAddr: guacdAddr},
		},
	}
	if n, err := users.CountAdmins(ctx); err == nil && n == 0 {
		log.Warn("no admin user exists; create one with `zanskar admin create`")
	}

	// Autoscaling: keep instance membership and health current (ADR 0011).
	go syncer.Run(ctx)

	// Recording retention: delete recordings past the admin-configured policy
	// (ADR 0015). Off until an admin sets a policy in the console.
	retention := &session.RetentionSweeper{Repo: sessionRepo, Storage: storage, Audit: auditLog, Log: log}
	go retention.Run(ctx, time.Hour)

	// Expire lapsed just-in-time access grants and audit each (ADR 0018).
	grantSweeper := &access.Sweeper{Repo: accessReqs, Audit: auditLog, Log: log}
	go grantSweeper.Run(ctx, time.Minute)

	// SIEM export: ship the audit chain to the configured sinks.
	var sinks []audit.Sink
	if cfg.SIEMSyslogAddr != "" {
		sinks = append(sinks, &audit.SyslogSink{Addr: cfg.SIEMSyslogAddr, Format: cfg.SIEMSyslogFormat, CAFile: cfg.SIEMSyslogCAFile})
	}
	if cfg.SIEMWebhookURL != "" {
		sinks = append(sinks, &audit.WebhookSink{URL: cfg.SIEMWebhookURL, Secret: cfg.SIEMWebhookSecret})
	}
	if len(sinks) > 0 {
		exporter := &audit.Exporter{Log: auditLog, Sinks: sinks, Logger: log}
		go exporter.Run(ctx)
		log.Info("audit export enabled", "sinks", len(sinks))
	}
	if cfg.AllowPlainHTTP && !cfg.ServesTLS() {
		log.Warn("ZANSKAR_ALLOW_PLAIN_HTTP=true: serving without TLS on a non-loopback address; development only")
	}

	// Housekeeping: drop auth sessions that can never be used again.
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := sessions.DeleteExpired(ctx); err != nil {
					log.Error("session sweep", "err", err)
				} else if n > 0 {
					log.Info("session sweep", "deleted", n)
				}
			}
		}
	}()

	log.Info("starting zanskar", "version", version.Version, "db_driver", cfg.DBDriver, "key_version", ring.ActiveVersion(), "web_ui", web.Enabled, "env_file", cfg.EnvFile)
	err = server.New(cfg, db, log, deps).ListenAndServe(ctx)
	if err == nil && restarter.Draining() {
		log.Info("stopped for a restart; the supervisor starts the next process", "supervisor", lifecycle.Supervisor())
	}
	return err
}

// ldapExternalAuth adapts the LDAP login helper to auth.ExternalAuthenticator,
// translating "no provider matched" into auth's sentinel so an ordinary miss
// is not logged as an error.
type ldapExternalAuth struct{ l *ldap.Login }

func (a ldapExternalAuth) Login(ctx context.Context, username, password, ip string) (*user.User, error) {
	u, err := a.l.Login(ctx, username, password, ip)
	if errors.Is(err, ldap.ErrNoMatch) {
		return nil, auth.ErrNoExternalIdentity
	}
	return u, err
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
