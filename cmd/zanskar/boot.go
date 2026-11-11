// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/albatroxxx/zanskar/internal/bootedit"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/settings"
)

// describeDSN names the database for the boot table without ever echoing a
// credential. A DSN can carry the password in three shapes (userinfo, a
// query parameter, a key=value token), so nothing is redacted from it;
// instead only the host and database name are extracted, and when they
// cannot be, the value says just that the driver is configured.
func describeDSN(driver, dsn string) string {
	if driver == config.DriverSQLite {
		// file:/var/lib/zanskar/zanskar.db?_pragma=... : the path, no pragmas.
		path := strings.TrimPrefix(dsn, "file:")
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		if path == "" || strings.HasPrefix(path, ":memory:") {
			return "sqlite (in memory)"
		}
		return "sqlite " + path
	}
	host, name := "", ""
	if strings.Contains(dsn, "://") {
		if u, err := url.Parse(dsn); err == nil {
			host, name = u.Hostname(), strings.TrimPrefix(u.Path, "/")
			if u.Port() != "" {
				host += ":" + u.Port()
			}
			if name == "" {
				name = u.Query().Get("dbname")
			}
		}
	} else {
		for tok := range strings.FieldsSeq(dsn) {
			k, v, ok := strings.Cut(tok, "=")
			if !ok {
				continue
			}
			switch k {
			case "host":
				host = v
			case "port":
				if host != "" {
					host += ":" + v
				}
			case "dbname":
				name = v
			}
		}
	}
	switch {
	case host != "" && name != "":
		return fmt.Sprintf("%s %s on %s", driver, name, host)
	case host != "":
		return driver + " on " + host
	default:
		return driver + " (configured)"
	}
}

// bootSettings lists what the environment fixed at start, for the panel's
// read-only section. Secrets are masked: the master key is named by its
// active version, the DSN loses any password.
func bootSettings(cfg *config.Config, keyVersion int) []settings.Boot {
	out := bootRows(cfg, keyVersion)
	for i := range out {
		switch {
		case out[i].Key == "tls":
			out[i].Editable, out[i].Raw = "preset", cfg.TLSMode
		case bootedit.Editable(out[i].EnvVar):
			out[i].Editable, out[i].Raw = "value", os.Getenv(out[i].EnvVar)
		}
	}
	return out
}

// bootRows lists the boot settings as the console shows them.
func bootRows(cfg *config.Config, keyVersion int) []settings.Boot {
	yesno := func(b bool) string {
		if b {
			return "true"
		}
		return "false"
	}
	set := func(s string) string {
		if s == "" {
			return "(not set)"
		}
		return s
	}
	proxies := make([]string, 0, len(cfg.TrustedProxies))
	for _, p := range cfg.TrustedProxies {
		proxies = append(proxies, p.String())
	}
	return []settings.Boot{
		{Key: "listen_addr", Title: "Listen address", EnvVar: "ZANSKAR_LISTEN_ADDR", Value: cfg.ListenAddr},
		{Key: "tls", Title: "TLS", EnvVar: "ZANSKAR_TLS_MODE, ZANSKAR_TLS_CERT, ZANSKAR_TLS_KEY", Value: map[string]string{
			config.TLSFile: "own certificate file: " + cfg.TLSCert, config.TLSManaged: "managed in the console (Settings, TLS certificate)", config.TLSProxy: "terminated by a proxy (plain HTTP on loopback)",
		}[cfg.TLSMode]},
		{Key: "tls_hosts", Title: "Certificate names", EnvVar: "ZANSKAR_TLS_HOSTS", Value: set(strings.Join(cfg.TLSHosts, ", ")), Description: "Extra names the managed certificate covers."},
		{Key: "http_redirect", Title: "HTTP redirect", EnvVar: "ZANSKAR_HTTP_REDIRECT_ADDR", Value: set(cfg.RedirectAddr)},
		{Key: "trust_proxy_tls", Title: "Trust proxy TLS", EnvVar: "ZANSKAR_TRUST_PROXY_TLS", Value: yesno(cfg.TrustProxyTLS), Description: "Marks cookies Secure."},
		{Key: "public_url", Title: "Public URL", EnvVar: "ZANSKAR_PUBLIC_URL", Value: set(cfg.PublicURL), Description: "Single sign-on redirects here."},
		{Key: "trusted_proxies", Title: "Trusted proxies", EnvVar: "ZANSKAR_TRUSTED_PROXIES", Value: strings.Join(proxies, ", "), Description: "Networks whose X-Forwarded-For is believed."},
		{Key: "allow_plain_http", Title: "Allow plain HTTP", EnvVar: "ZANSKAR_ALLOW_PLAIN_HTTP", Value: yesno(cfg.AllowPlainHTTP), Description: "Development only."},
		{Key: "db", Title: "Database", EnvVar: "ZANSKAR_DB_DRIVER, ZANSKAR_DB_DSN", Value: describeDSN(cfg.DBDriver, cfg.DBDSN)},
		masterKeySetting(cfg, keyVersion),
		{Key: "recordings_dir", Title: "Recordings directory", EnvVar: "ZANSKAR_RECORDINGS_DIR", Value: cfg.RecordingsDir},
		{Key: "recordings_s3", Title: "Recordings in S3", EnvVar: "ZANSKAR_RECORDINGS_S3_*", Value: set(cfg.RecordingsS3Bucket), Description: "Recording storage above overrides it."},
		{Key: "docker_path", Title: "Container runtime", EnvVar: "ZANSKAR_DOCKER_PATH", Value: map[bool]string{true: cfg.DockerPath, false: "docker (on PATH)"}[cfg.DockerPath != ""], Description: "For database and application sessions."},
		{Key: "database_max_sessions", Title: "Database session cap", EnvVar: "ZANSKAR_DATABASE_MAX_SESSIONS", Value: map[bool]string{true: strconv.Itoa(cfg.DatabaseMaxSessions), false: "no cap"}[cfg.DatabaseMaxSessions > 0], Description: "0 lifts the cap."},
		{Key: "apps_max_sessions", Title: "Application session cap", EnvVar: "ZANSKAR_APPS_MAX_SESSIONS", Value: map[bool]string{true: strconv.Itoa(cfg.AppsMaxSessions), false: "no cap"}[cfg.AppsMaxSessions > 0], Description: "0 lifts the cap."},
		{Key: "issuer", Title: "Authenticator issuer", EnvVar: "ZANSKAR_ISSUER", Value: cfg.Issuer},
		{Key: "siem", Title: "SIEM export", EnvVar: "ZANSKAR_SIEM_*", Value: map[bool]string{true: "configured", false: "(not set)"}[cfg.SIEMSyslogAddr != "" || cfg.SIEMWebhookURL != ""]},
		{Key: "log_format", Title: "Log format", EnvVar: "ZANSKAR_LOG_FORMAT", Value: cfg.LogFormat, Description: "json or text."},
		{Key: "aws_gateway_principal", Title: "AWS gateway principal", EnvVar: "ZANSKAR_AWS_GATEWAY_PRINCIPAL", Value: set(cfg.AWSGatewayPrincipal), Description: "Detected when unset."},
	}
}

// masterKeySetting says where the master key came from, never the key itself.
func masterKeySetting(cfg *config.Config, keyVersion int) settings.Boot {
	s := settings.Boot{Key: "master_key", Title: "Master key", EnvVar: "ZANSKAR_MASTER_KEY",
		Value: fmt.Sprintf("set (data-key version %d active)", keyVersion)}
	if cfg.MasterKeyFile != "" {
		s.EnvVar = "ZANSKAR_MASTER_KEY_FILE"
		s.Value = fmt.Sprintf("read from %s (data-key version %d active)", cfg.MasterKeyFile, keyVersion)
	}
	return s
}
