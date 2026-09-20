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
	RequireMFA      bool
	LogLevel        string
	LogFormat       string
	ShutdownTimeout time.Duration
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
		ListenAddr:      envOr("ZANSKAR_LISTEN_ADDR", "127.0.0.1:8443"),
		AdminListenAddr: os.Getenv("ZANSKAR_ADMIN_LISTEN_ADDR"),
		DBDriver:        envOr("ZANSKAR_DB_DRIVER", DriverSQLite),
		DBDSN:           envOr("ZANSKAR_DB_DSN", "file:zanskar.db?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"),
		TLSCert:         os.Getenv("ZANSKAR_TLS_CERT"),
		TLSKey:          os.Getenv("ZANSKAR_TLS_KEY"),
		GuacdAddr:       envOr("ZANSKAR_GUACD_ADDR", "127.0.0.1:4822"),
		TrustProxyTLS:   os.Getenv("ZANSKAR_TRUST_PROXY_TLS") == "true",
		Issuer:          envOr("ZANSKAR_ISSUER", "Zanskar"),
		RequireMFA:      envOr("ZANSKAR_REQUIRE_MFA", "true") != "false",
		LogLevel:        strings.ToLower(envOr("ZANSKAR_LOG_LEVEL", "info")),
		LogFormat:       strings.ToLower(envOr("ZANSKAR_LOG_FORMAT", "json")),
		ShutdownTimeout: 20 * time.Second,
	}

	var errs []error

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
	if c.TLSCert == "" && !isLoopback(c.ListenAddr) {
		errs = append(errs, errors.New("refusing to serve plain HTTP on a non-loopback address; set ZANSKAR_TLS_CERT/ZANSKAR_TLS_KEY or terminate TLS in front and bind to loopback"))
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

	if raw := os.Getenv("ZANSKAR_MASTER_KEY"); raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("ZANSKAR_MASTER_KEY is not valid base64: %w", err))
		} else if len(key) != 32 {
			errs = append(errs, fmt.Errorf("ZANSKAR_MASTER_KEY must decode to 32 bytes, got %d", len(key)))
		} else {
			c.MasterKey = key
		}
	} else if opts.RequireMasterKey {
		errs = append(errs, errors.New("ZANSKAR_MASTER_KEY is required; generate one with `zanskar keygen`"))
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
