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
	TLSCert         string
	TLSKey          string
	GuacdAddr       string
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
}

// Options tunes what Load requires.
type Options struct {
	// RequireMasterKey makes a missing ZANSKAR_MASTER_KEY fatal. `serve` sets it;
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
		GuacdAddr:            os.Getenv("ZANSKAR_GUACD_ADDR"), // empty disables RDP and VNC
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
	if c.TLSCert == "" && !isLoopback(c.ListenAddr) && !c.AllowPlainHTTP {
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

	raw := os.Getenv("ZANSKAR_MASTER_KEY")
	switch {
	case raw == "" && opts.RequireMasterKey:
		errs = append(errs, errors.New("ZANSKAR_MASTER_KEY is required; generate one with `zanskar keygen`"))
	case raw != "":
		key, err := base64.StdEncoding.DecodeString(raw)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("ZANSKAR_MASTER_KEY is not valid base64: %w", err))
		case len(key) != 32:
			errs = append(errs, fmt.Errorf("ZANSKAR_MASTER_KEY must decode to 32 bytes, got %d", len(key)))
		default:
			c.MasterKey = key
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// SecureCookies reports whether browser cookies should carry the Secure flag.
func (c *Config) SecureCookies() bool {
	return c.TLSCert != "" || c.TrustProxyTLS
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
