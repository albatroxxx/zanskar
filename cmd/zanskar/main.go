// SPDX-License-Identifier: Apache-2.0

// Command zanskar is the single binary for the Zanskar access gateway.
//
//	zanskar serve     run the gateway
//	zanskar migrate   apply pending database migrations and exit
//	zanskar keygen    print a new base64 master key for ZANSKAR_MASTER_KEY
//	zanskar audit verify   walk the audit log and check the hash chain, anchors and id sequence
//	zanskar audit anchor   sign the newest audit event and print the anchor line
//	zanskar healthcheck   ask the running gateway whether it is ready (container health checks)
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
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/albatroxxx/zanskar/internal/access"
	"github.com/albatroxxx/zanskar/internal/apps"
	"github.com/albatroxxx/zanskar/internal/asg"
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/cloud"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/connect"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/dbgw"
	"github.com/albatroxxx/zanskar/internal/group"
	"github.com/albatroxxx/zanskar/internal/idp"
	idpadmin "github.com/albatroxxx/zanskar/internal/idp/adminapi"
	"github.com/albatroxxx/zanskar/internal/idp/ldap"
	"github.com/albatroxxx/zanskar/internal/idp/oidc"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/lifecycle"
	"github.com/albatroxxx/zanskar/internal/logring"
	"github.com/albatroxxx/zanskar/internal/overview"
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
	"github.com/albatroxxx/zanskar/internal/update"
	"github.com/albatroxxx/zanskar/internal/user"
	"github.com/albatroxxx/zanskar/internal/user/adminapi"
	"github.com/albatroxxx/zanskar/internal/version"
	"github.com/albatroxxx/zanskar/web"
)

func main() { os.Exit(run(os.Args[1:])) }

// errUsage reports a malformed command line whose usage text has already
// been printed; it exits 2 rather than 1.
var errUsage = errors.New("usage")

// run dispatches a command line (without the program name) and returns the
// process exit code: 0 on success, 1 on a failed command, 2 on bad usage.
func run(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	var err error
	switch args[0] {
	case "serve":
		err = runServe()
	case "migrate":
		err = runMigrate()
	case "init":
		err = runInit(args[1:])
	case "backup":
		err = runBackup(args[1:])
	case "restore":
		err = runRestore(args[1:])
	case "keygen":
		err = runKeygen()
	case "key":
		err = runKey(args[1:])
	case "dbproxy":
		err = runDBProxy()
	case "healthcheck":
		err = runHealthcheck()
	case "version":
		fmt.Println(version.Version)
	case "admin":
		err = runAdmin(args[1:])
	case "audit":
		err = runAudit(args[1:])
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		return 2
	}
	switch {
	case errors.Is(err, errUsage):
		return 2
	case err != nil:
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: zanskar <init|serve|migrate|backup|restore|keygen|key status|key rotate|key rotate-master|admin create|admin reset-mfa|audit verify|audit anchor|audit reseal|dbproxy|healthcheck|version>")
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serve(ctx)
}

// serve runs the gateway until ctx ends (SIGINT or SIGTERM under runServe) or
// a console-requested restart has drained. It returns nil on a clean stop.
func serve(ctx context.Context) error {
	startedAt := time.Now().UTC()
	// Taken before anything else reads or touches the environment: it is
	// what the environment file is later compared against (ADR 0020).
	startedEnv := lifecycle.SnapshotEnv()
	cfg, err := config.Load(config.Options{RequireMasterKey: true})
	if err != nil {
		return err
	}
	// Read once, the secrets leave the process's environment, which a child
	// started without one of its own would inherit. The snapshot above keeps
	// the restart check working, and a restart is a new process
	// (lifecycle.Controller).
	config.DropSecretEnv()
	log, logLevel, logs := newLeveledLogger(cfg)
	// Settings that are set but do nothing here are said out loud (B13).
	for _, w := range cfg.Warnings {
		log.Warn(w)
	}
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
		tlsMgr = &tlscert.Manager{Repo: tlscert.NewRepo(db, ring), Log: log, Hosts: tlscert.LocalHosts(cfg.ListenAddr, cfg.TLSHosts...)}
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
	envSettings, envErrs := settings.EnvValues()
	if len(envErrs) > 0 {
		return fmt.Errorf("settings from the environment: %w", errors.Join(envErrs...))
	}
	runtime := settings.NewService(settings.NewRepo(db), envSettings, bootSettings(cfg, ring.ActiveVersion()))
	runtime.Logger = log
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
	// The apps domain (ADR 0033) must not hold the console's own host, or
	// the console's requests would be dispatched to the proxy. Checked when
	// the console sets it, and once here for a value already stored or in
	// the environment.
	appsDomain := func() string { return runtime.String(settings.KeyAppsDomain) }
	appsDomainCheck := appsDomainChecker(cfg.PublicURL)
	runtime.Check(settings.KeyAppsDomain, appsDomainCheck)
	if err := appsDomainCheck(appsDomain()); err != nil {
		return fmt.Errorf("apps domain %q %w", appsDomain(), err)
	}
	if tlsMgr != nil {
		tlsMgr.AppsDomain = appsDomain
	}

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
	// Signs the audit anchors (ADR 0008), derived from the master key like
	// the CSRF key; `zanskar key rotate-master` re-signs the stored anchors.
	anchorKey, err := audit.AnchorKey(cfg.MasterKey)
	if err != nil {
		return err
	}
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
	authHandler.ExternalLogin = ldapExternalAuth{ldap.NewLogin(idpRepo, provisioner, auditLog, log)}
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
	// One set of address rules for every connection to a target: probes, the
	// autoscaling sync and sessions. A listener bound to one address makes
	// that address the gateway's own, refused as a target.
	prober := &target.Prober{Self: target.ListenIP(cfg.ListenAddr)}
	syncer := &asg.Syncer{Repo: asgRepo, Providers: cloudProviders, Prober: prober, Registry: registry, Audit: auditLog, Log: log}
	// The connect handler runs the bridges; the user, group and policy admin
	// handlers hand it the changes that end live sessions (ADR 0013).
	connectHandler := &connect.Handler{Targets: targets, Policies: policies, Access: accessReqs, Vault: vault, Sessions: sessionRepo, Tickets: ticket.NewStore(),
		Registry: registry, Storage: storage, Audit: auditLog, Log: log, MFAEnrolled: totp.Enrolled, GuacdAddr: guacdAddr, Draining: restarter.Draining,
		DockerPath: cfg.DockerPath, DBMaxSessions: cfg.DatabaseMaxSessions, DBProxyImage: func() string { return runtime.String(settings.KeyDBProxyImage) },
		Prober: prober, ASGs: asgRepo, Cloud: cloudProviders}
	// A sign-in through an identity provider that removes the user from a
	// mapped group ends what that group granted, as an admin's removal does.
	provisioner.Revoker = connectHandler
	// Applications (ADR 0033): the proxy shares the connect flow's admission
	// gate and registry, lists its applications through /me/targets, and
	// says when an application may be enrolled.
	appsHandler := &apps.Handler{Targets: targets, Gate: &access.Gate{Policies: policies, Grants: accessReqs, MFAEnrolled: totp.Enrolled},
		Sessions: sessionRepo, Auth: sessions, Repo: apps.NewRepo(db), Registry: registry, Audit: auditLog, Log: log, Prober: prober,
		Domain: appsDomain, PublicURL: cfg.PublicURL, Draining: restarter.Draining}
	if tlsMgr != nil {
		appsHandler.TLSReady = tlsMgr.AppsReady
	}
	connectHandler.AppURL = appsHandler.URL
	if err := appsHandler.Resume(ctx); err != nil {
		return fmt.Errorf("application sessions: %w", err)
	}
	go appsHandler.Run(ctx, time.Minute)
	// The bell (ADR 0032): once a day, is there a newer release? The
	// runtime setting is read before each check so a switch-off applies live.
	versionCheck := &update.Checker{URL: cfg.UpdateManifestURL, Current: version.Version, Enabled: func() bool { return runtime.Bool(settings.KeyUpdateCheck) }, Log: log}
	go versionCheck.Run(ctx)
	deps := server.Deps{
		TLS:            tlsMgr,
		Apps:           appsHandler,
		AuthMiddleware: &auth.Middleware{Sessions: sessions, Users: users, Log: log},
		Auth:           authHandler,
		Handlers: []server.Registrar{
			appsHandler,
			&adminapi.AdminHandler{Users: users, Sessions: sessions, TOTP: totp, Revoker: connectHandler, Audit: auditLog, Log: log},
			&group.AdminHandler{Groups: groups, Revoker: connectHandler, Audit: auditLog, Log: log},
			&idpadmin.AdminHandler{Providers: idpRepo, Audit: auditLog, Log: log, LDAPTester: &ldap.Authenticator{}},
			&oidc.Handler{Providers: idpRepo, Provisioner: provisioner, Sessions: sessions, Audit: auditLog, Log: log, StateKey: stateKey, MFAEnrolled: totp.Enrolled, RequireMFA: requireMFA,
				BaseURL: cfg.PublicURL},
			&credential.AdminHandler{Vault: vault, Audit: auditLog, Log: log},
			&target.AdminHandler{Repo: targets, Prober: prober, Policies: policies, Live: registry, Vault: vault, AppsReady: appsHandler.Ready, Audit: auditLog, Log: log},
			&policy.AdminHandler{Repo: policies, Users: users, Revoker: connectHandler, Audit: auditLog, Log: log},
			&access.Handler{Requests: accessReqs, Policies: policies, Targets: targets, ASGs: asgRepo, Audit: auditLog, Log: log},
			&asg.AdminHandler{Repo: asgRepo, Sync: syncer.SyncGroup, Identity: awsIdentity, Providers: asg.AWSFresh(), Policies: policies, Live: registry, Vault: vault, Audit: auditLog, Log: log},
			&session.Handler{Repo: sessionRepo, Audit: auditLog, AnchorKey: anchorKey, Registry: registry, Storage: storage, Log: log},
			&overview.Handler{Sessions: sessionRepo, Requests: accessReqs, Targets: targets, ASGs: asgRepo, Audit: auditLog, Log: log},
			&update.Handler{Checker: versionCheck, Log: log, StateDir: cfg.StateDir, Supervisor: lifecycle.Supervisor},
			&settings.Handler{Service: runtime, Audit: auditLog, Log: log},
			&recstorage.Handler{Manager: storageMgr, Audit: auditLog, Log: log},
			&lifecycle.Handler{Drift: drift, Controller: restarter, Audit: auditLog, Log: log, StartedAt: startedAt,
				DatabasePath: dbFileForMetrics(cfg.DBDSN), RecordingsPath: cfg.RecordingsDir, GuacdAddr: guacdAddr, StateDir: cfg.StateDir},
			&logring.API{Ring: logs, Audit: auditLog, Log: log},
			&tlscert.Handler{Manager: tlsMgr, Mode: cfg.TLSMode, Audit: auditLog, Log: log},
			connectHandler,
			&connect.ShadowHandler{Registry: registry, Audit: auditLog, Log: log, GuacdAddr: guacdAddr},
			consoleCLI(cfg, sessions, totp, auditLog, log),
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

	// Renew the self-signed certificate inside thirty days of its end while
	// the gateway runs, not only at start (ADR 0021, B9).
	if tlsMgr != nil {
		go tlsMgr.Run(ctx, 6*time.Hour)
	}

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

	// Audit anchors (ADR 0008): sign the chain head now and every hour. Each
	// new anchor is logged as "audit anchor"; that journal line is the copy
	// kept outside the database, for `zanskar audit verify --anchor`.
	anchorer := &audit.Anchorer{Log: auditLog, Key: anchorKey, Logger: log, Interval: time.Hour}
	go anchorer.Run(ctx)
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

	// Database sessions (ADR 0017): the containers and networks a crashed
	// process or a failed teardown left behind are removed by label, now and
	// every five minutes; a session this process still runs is never touched.
	// How loudly a failing pass is reported is reapNotice's: once, not every
	// pass, and never for a host with no container CLI.
	go func() {
		live := func(id string) bool { _, ok := registry.Get(id); return ok }
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		var notice reapNotice
		for {
			n, err := dbgw.Reap(ctx, cfg.DockerPath, live)
			if ctx.Err() != nil {
				return // shutting down: a pass cut short says nothing about Docker
			}
			if n > 0 {
				log.Info("database session reaper removed leftovers", "removed", n)
			}
			if level, ok := notice.level(err); ok {
				log.Log(ctx, level, "database session reaper cannot list containers; database sessions will not work until it can", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
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

// appsDomainChecker returns the rule the apps domain (ADR 0033) must pass
// beside its shape: it must not be, or be a parent of, the console's own
// host from ZANSKAR_PUBLIC_URL, or the console's own requests would reach the
// applications proxy. With no public URL there is nothing to compare, and
// the proxy is not served anyway (apps.Handler.Ready).
func appsDomainChecker(publicURL string) func(domain string) error {
	host := ""
	if u, err := url.Parse(publicURL); err == nil {
		host = strings.ToLower(u.Hostname())
	}
	return func(domain string) error {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" || host == "" {
			return nil
		}
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return fmt.Errorf("holds the console's own host %s; applications must live under a domain of their own, such as apps.%s", host, host)
		}
		return nil
	}
}

// dbFileForMetrics is the file behind a SQLite DSN, for the disk-space
// metric; empty for Postgres, where the volume is not this host's concern.
func dbFileForMetrics(dsn string) string {
	if !strings.HasPrefix(dsn, "file:") {
		return ""
	}
	path, err := sqliteFilePath(dsn)
	if err != nil {
		return ""
	}
	return path
}
