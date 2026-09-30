// SPDX-License-Identifier: Apache-2.0

// Package config loads and validates runtime configuration from the environment.
// Zanskar deliberately has no config file: secrets belong in the environment or a
// secret manager, and everything else is small enough to be explicit.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

// Driver names accepted by ZANSKAR_DB_DRIVER.
const (
	DriverSQLite   = "sqlite"
	DriverPostgres = "postgres"
)

// Config is the fully validated runtime configuration.
type Config struct {
	ListenAddr      string
	AdminListenAddr string // optional; empty means admin routes share ListenAddr
	DBDriver        string
	DBDSN           string
	MasterKey       []byte // 32 bytes; nil only when explicitly allowed (e.g. `migrate`)
	// MasterKeyFile is the file the key was read from when it came from
	// ZANSKAR_MASTER_KEY_FILE rather than the environment itself.
	MasterKeyFile string
	TLSCert       string
	TLSKey        string
	// TLSMode is how the listener is protected: TLSFile serves the
	// certificate in TLSCert/TLSKey, TLSManaged serves the certificate the
	// console manages (self-signed until one is uploaded, ADR 0021), and
	// TLSProxy speaks plain HTTP for a TLS-terminating proxy in front.
	// Derived from the other variables when ZANSKAR_TLS_MODE is unset, so
	// an existing install keeps its behaviour.
	TLSMode string
	// TLSHosts are extra names or addresses a managed certificate should
	// cover, beyond the ones the machine can work out for itself. A cloud
	// instance cannot: its public address is translated upstream and never
	// appears on an interface, so it has to be named here or the certificate
	// will not carry it.
	TLSHosts []string
	// RedirectAddr, when set, is a plain-HTTP listener that answers every
	// request with a redirect to the HTTPS listener (":80" on a default
	// install). Only meaningful when the gateway serves TLS.
	RedirectAddr string
	GuacdAddr    string
	// DockerPath is the container CLI used to spawn ephemeral database session
	// containers (ADR 0017); empty defaults to "docker" on PATH. Set it to an
	// absolute path or to "podman" for alternate runtimes.
	DockerPath string
	// TrustProxyTLS marks cookies Secure when TLS terminates in front of a
	// loopback-bound Zanskar. Never set it when clients reach Zanskar over
	// plain HTTP.
	TrustProxyTLS bool
	// Issuer is the name shown in authenticator apps.
	Issuer string
	// RequireMFA forces every password user to enroll an authenticator before
	// the session becomes usable. Default true; set ZANSKAR_REQUIRE_MFA=false
	// only for throwaway development databases.
	RequireMFA bool
	// RecordingsDir is where session recordings are written (local storage).
	RecordingsDir string
	// RecordingsS3Bucket switches recordings to an S3-compatible bucket.
	// Empty keeps the local directory backend.
	RecordingsS3Bucket   string
	RecordingsS3Prefix   string
	RecordingsS3Region   string
	RecordingsS3Endpoint string
	RecordingsS3KMSKey   string
	// RecordingsSpoolDir holds in-progress recordings before upload to S3.
	RecordingsSpoolDir string
	// SIEM export: audit events are shipped to any sink configured here.
	SIEMSyslogAddr    string // tcp://host:port or tls://host:port
	SIEMSyslogFormat  string // cef | json
	SIEMSyslogCAFile  string
	SIEMWebhookURL    string
	SIEMWebhookSecret []byte
	// TrustedProxies lists the networks whose X-Forwarded-For header is believed.
	// The gateway normally runs behind a TLS-terminating proxy on loopback, so
	// without this every request would be attributed to the proxy rather than the
	// real client. Only addresses in this list may set the client address, since
	// anyone can send the header.
	TrustedProxies []netip.Prefix
	// AllowPlainHTTP permits listening without TLS on a non-loopback address.
	// Development only (docker compose); every response is sent in clear.
	AllowPlainHTTP bool
	// AWSGatewayPrincipal is the ARN the gateway runs as (instance profile or
	// user). It is rendered into the trust policy shown to admins enrolling
	// an autoscaling group; empty leaves a placeholder.
	AWSGatewayPrincipal string
	LogLevel            string
	LogFormat           string
	ShutdownTimeout     time.Duration
	// EnvFile is the environment file the process was started from, when
	// there is one, so the console can tell an operator it changed and a
	// restart is due (ADR 0020). ZANSKAR_ENV_FILE names it; otherwise the
	// packaged path is used when it exists. Containers usually have none.
	EnvFile string
}

// DefaultEnvFile is where the package and `zanskar init` put the file.
const DefaultEnvFile = "/etc/zanskar/env"

// TLS modes.
const (
	TLSFile    = "file"
	TLSManaged = "managed"
	TLSProxy   = "proxy"
)

// ServesTLS reports whether the gateway terminates TLS itself.
func (c *Config) ServesTLS() bool {
	return c.TLSMode == TLSFile || c.TLSMode == TLSManaged
}

// Options tunes what Load requires.
type Options struct {
	// RequireMasterKey makes a missing master key (ZANSKAR_MASTER_KEY or
	// ZANSKAR_MASTER_KEY_FILE) fatal. `serve` sets it;
	// `migrate` and `keygen` do not.
	RequireMasterKey bool
}

// Load reads the environment and returns a validated Config.
func Load(opts Options) (*Config, error) {
	c := &Config{
		ListenAddr:           envOr("ZANSKAR_LISTEN_ADDR", "127.0.0.1:8443"),
		AdminListenAddr:      os.Getenv("ZANSKAR_ADMIN_LISTEN_ADDR"),
		DBDriver:             envOr("ZANSKAR_DB_DRIVER", DriverSQLite),
		DBDSN:                envOr("ZANSKAR_DB_DSN", "file:zanskar.db?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"),
		TLSCert:              os.Getenv("ZANSKAR_TLS_CERT"),
		TLSKey:               os.Getenv("ZANSKAR_TLS_KEY"),
		TLSHosts:             splitList(os.Getenv("ZANSKAR_TLS_HOSTS")),
		GuacdAddr:            os.Getenv("ZANSKAR_GUACD_ADDR"),  // empty disables RDP and VNC
		DockerPath:           os.Getenv("ZANSKAR_DOCKER_PATH"), // empty defaults to "docker" on PATH
		TrustProxyTLS:        os.Getenv("ZANSKAR_TRUST_PROXY_TLS") == "true",
		Issuer:               envOr("ZANSKAR_ISSUER", "Zanskar"),
		RequireMFA:           envOr("ZANSKAR_REQUIRE_MFA", "true") != "false",
		RecordingsDir:        envOr("ZANSKAR_RECORDINGS_DIR", "data/recordings"),
		RecordingsS3Bucket:   os.Getenv("ZANSKAR_RECORDINGS_S3_BUCKET"),
		RecordingsS3Prefix:   envOr("ZANSKAR_RECORDINGS_S3_PREFIX", "recordings/"),
		RecordingsS3Region:   os.Getenv("ZANSKAR_RECORDINGS_S3_REGION"),
		RecordingsS3Endpoint: os.Getenv("ZANSKAR_RECORDINGS_S3_ENDPOINT"),
		RecordingsS3KMSKey:   os.Getenv("ZANSKAR_RECORDINGS_S3_KMS_KEY"),
		RecordingsSpoolDir:   os.Getenv("ZANSKAR_RECORDINGS_SPOOL_DIR"),
		AWSGatewayPrincipal:  os.Getenv("ZANSKAR_AWS_GATEWAY_PRINCIPAL"),
		SIEMSyslogAddr:       os.Getenv("ZANSKAR_SIEM_SYSLOG_ADDR"),
		SIEMSyslogFormat:     strings.ToLower(envOr("ZANSKAR_SIEM_SYSLOG_FORMAT", "cef")),
		SIEMSyslogCAFile:     os.Getenv("ZANSKAR_SIEM_SYSLOG_CA"),
		SIEMWebhookURL:       os.Getenv("ZANSKAR_SIEM_WEBHOOK_URL"),
		SIEMWebhookSecret:    []byte(os.Getenv("ZANSKAR_SIEM_WEBHOOK_SECRET")),
		AllowPlainHTTP:       os.Getenv("ZANSKAR_ALLOW_PLAIN_HTTP") == "true",
		TrustedProxies:       nil, // parsed below so a bad entry is a config error
		LogLevel:             strings.ToLower(envOr("ZANSKAR_LOG_LEVEL", "info")),
		LogFormat:            strings.ToLower(envOr("ZANSKAR_LOG_FORMAT", "json")),
		ShutdownTimeout:      20 * time.Second,
		EnvFile:              os.Getenv("ZANSKAR_ENV_FILE"),
		TLSMode:              strings.ToLower(os.Getenv("ZANSKAR_TLS_MODE")),
		RedirectAddr:         os.Getenv("ZANSKAR_HTTP_REDIRECT_ADDR"),
	}
	if c.TLSMode == "" {
		if c.TLSCert != "" {
			c.TLSMode = TLSFile
		} else {
			c.TLSMode = TLSProxy
		}
	}
	if c.EnvFile == "" {
		if _, err := os.Stat(DefaultEnvFile); err == nil {
			c.EnvFile = DefaultEnvFile
		}
	}

	var errs []error

	// Loopback by default: the documented deployment terminates TLS in a proxy on
	// the same host. Set ZANSKAR_TRUSTED_PROXIES to "" to trust nothing.
	for _, raw := range strings.Split(envOr("ZANSKAR_TRUSTED_PROXIES", "127.0.0.1/32,::1/128"), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// Accept a bare address as a single-host network, which is what operators
		// usually mean when naming one proxy.
		if !strings.Contains(raw, "/") {
			addr, err := netip.ParseAddr(raw)
			if err != nil {
				errs = append(errs, fmt.Errorf("ZANSKAR_TRUSTED_PROXIES: %q: %w", raw, err))
				continue
			}
			c.TrustedProxies = append(c.TrustedProxies, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("ZANSKAR_TRUSTED_PROXIES: %q: %w", raw, err))
			continue
		}
		c.TrustedProxies = append(c.TrustedProxies, p.Masked())
	}

	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		errs = append(errs, fmt.Errorf("ZANSKAR_LISTEN_ADDR: %w", err))
	}
	if c.AdminListenAddr != "" {
		if _, _, err := net.SplitHostPort(c.AdminListenAddr); err != nil {
			errs = append(errs, fmt.Errorf("ZANSKAR_ADMIN_LISTEN_ADDR: %w", err))
		}
	}
	if c.DBDriver != DriverSQLite && c.DBDriver != DriverPostgres {
		errs = append(errs, fmt.Errorf("ZANSKAR_DB_DRIVER must be %q or %q", DriverSQLite, DriverPostgres))
	}
	if c.DBDSN == "" {
		errs = append(errs, errors.New("ZANSKAR_DB_DSN must not be empty"))
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		errs = append(errs, errors.New("ZANSKAR_TLS_CERT and ZANSKAR_TLS_KEY must be set together"))
	}
	switch c.TLSMode {
	case TLSFile:
		if c.TLSCert == "" {
			errs = append(errs, errors.New("ZANSKAR_TLS_MODE=file needs ZANSKAR_TLS_CERT and ZANSKAR_TLS_KEY"))
		}
	case TLSManaged, TLSProxy:
	default:
		errs = append(errs, fmt.Errorf("ZANSKAR_TLS_MODE %q is not file, managed or proxy", c.TLSMode))
	}
	if c.RedirectAddr != "" {
		if _, _, err := net.SplitHostPort(c.RedirectAddr); err != nil {
			errs = append(errs, fmt.Errorf("ZANSKAR_HTTP_REDIRECT_ADDR: %w", err))
		} else if !c.ServesTLS() {
			errs = append(errs, errors.New("ZANSKAR_HTTP_REDIRECT_ADDR needs the gateway to serve TLS (ZANSKAR_TLS_MODE=managed or a certificate)"))
		} else if c.RedirectAddr == c.ListenAddr {
			errs = append(errs, errors.New("ZANSKAR_HTTP_REDIRECT_ADDR must differ from ZANSKAR_LISTEN_ADDR"))
		}
	}
	if !c.ServesTLS() && !isLoopback(c.ListenAddr) && !c.AllowPlainHTTP {
		errs = append(errs, errors.New("refusing to serve plain HTTP on a non-loopback address; set ZANSKAR_TLS_CERT/ZANSKAR_TLS_KEY, bind to loopback behind a TLS proxy, or set ZANSKAR_ALLOW_PLAIN_HTTP=true for development only"))
	}
	if c.SIEMSyslogAddr != "" && !strings.HasPrefix(c.SIEMSyslogAddr, "tcp://") && !strings.HasPrefix(c.SIEMSyslogAddr, "tls://") {
		errs = append(errs, errors.New("ZANSKAR_SIEM_SYSLOG_ADDR must start with tcp:// or tls://"))
	}
	if c.SIEMSyslogFormat != "cef" && c.SIEMSyslogFormat != "json" {
		errs = append(errs, errors.New("ZANSKAR_SIEM_SYSLOG_FORMAT must be cef or json"))
	}
	if c.SIEMWebhookURL != "" {
		if !strings.HasPrefix(c.SIEMWebhookURL, "https://") {
			errs = append(errs, errors.New("ZANSKAR_SIEM_WEBHOOK_URL must be https"))
		}
		if len(c.SIEMWebhookSecret) < 16 {
			errs = append(errs, errors.New("ZANSKAR_SIEM_WEBHOOK_SECRET must be at least 16 characters"))
		}
	}
	if c.RecordingsS3Endpoint != "" && !strings.HasPrefix(c.RecordingsS3Endpoint, "https://") && !strings.HasPrefix(c.RecordingsS3Endpoint, "http://") {
		errs = append(errs, errors.New("ZANSKAR_RECORDINGS_S3_ENDPOINT must be an http(s) URL"))
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("ZANSKAR_LOG_LEVEL %q is not one of debug, info, warn, error", c.LogLevel))
	}
	switch c.LogFormat {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("ZANSKAR_LOG_FORMAT %q is not json or text", c.LogFormat))
	}

	// The master key comes from the environment or from a file of its own.
	// The file keeps it apart from the other settings (and from anything that
	// prints the environment), and can be replaced without touching them.
	raw, source := os.Getenv("ZANSKAR_MASTER_KEY"), "ZANSKAR_MASTER_KEY"
	path := os.Getenv("ZANSKAR_MASTER_KEY_FILE")
	if path != "" {
		if raw != "" {
			errs = append(errs, errors.New("set ZANSKAR_MASTER_KEY or ZANSKAR_MASTER_KEY_FILE, not both"))
		} else if v, err := readKeyFile(path); err != nil {
			errs = append(errs, fmt.Errorf("ZANSKAR_MASTER_KEY_FILE: %w", err))
		} else {
			raw, source, c.MasterKeyFile = v, "the key in "+path, path
		}
	}
	switch {
	case raw == "" && opts.RequireMasterKey && path == "": // a named file already said what is wrong with it
		errs = append(errs, errors.New("ZANSKAR_MASTER_KEY (or ZANSKAR_MASTER_KEY_FILE) is required; generate one with `zanskar keygen`"))
	case raw != "":
		key, err := base64.StdEncoding.DecodeString(raw)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s is not valid base64: %w", source, err))
		case len(key) != 32:
			errs = append(errs, fmt.Errorf("%s must decode to 32 bytes, got %d", source, len(key)))
		default:
			c.MasterKey = key
		}
	case c.MasterKeyFile != "":
		errs = append(errs, fmt.Errorf("%s is empty", source))
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// SecureCookies reports whether browser cookies should carry the Secure flag.
func (c *Config) SecureCookies() bool {
	return c.ServesTLS() || c.TrustProxyTLS
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// splitList reads a comma-separated environment value, trimming blanks.
func splitList(v string) []string {
	var out []string
	for _, raw := range strings.Split(v, ",") {
		if t := strings.TrimSpace(raw); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// readKeyFile reads a master key file. It must be a regular file that only
// its owner can read or write: a key readable by other local accounts is a
// key those accounts hold, so the gateway refuses to start rather than use it.
func readKeyFile(path string) (string, error) {
	info, err := os.Stat(path) // #nosec G703 -- the operator's own ZANSKAR_MASTER_KEY_FILE, not request input
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("%s is mode %04o; only its owner may read it (chmod 0400 %s)", path, perm, path)
	}
	if info.Size() > 1024 {
		return "", fmt.Errorf("%s is %d bytes; a master key file holds one base64 line", path, info.Size())
	}
	b, err := os.ReadFile(path) // #nosec G304 G703 -- the operator's own ZANSKAR_MASTER_KEY_FILE, not request input
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
