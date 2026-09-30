// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"strings"

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
		for _, tok := range strings.Fields(dsn) {
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
		{Key: "listen_addr", Title: "Listen address", EnvVar: "ZANSKAR_LISTEN_ADDR", Value: cfg.ListenAddr, Description: "Where the gateway accepts connections."},
		{Key: "admin_listen_addr", Title: "Admin listen address", EnvVar: "ZANSKAR_ADMIN_LISTEN_ADDR", Value: set(cfg.AdminListenAddr), Description: "Separate listener for admin routes; empty shares the main one."},
		{Key: "tls", Title: "TLS", EnvVar: "ZANSKAR_TLS_MODE, ZANSKAR_TLS_CERT, ZANSKAR_TLS_KEY", Value: map[string]string{
			config.TLSFile: "own certificate file: " + cfg.TLSCert, config.TLSManaged: "managed in the console (Settings, TLS certificate)", config.TLSProxy: "terminated by a proxy (plain HTTP on loopback)",
		}[cfg.TLSMode], Description: "Serve TLS with a managed or a file certificate, or trust a proxy in front."},
		{Key: "tls_hosts", Title: "Certificate names", EnvVar: "ZANSKAR_TLS_HOSTS", Value: set(strings.Join(cfg.TLSHosts, ", ")), Description: "Extra names a managed certificate covers, beyond this machine's own. A cloud instance's public address is not on an interface, so it belongs here."},
		{Key: "http_redirect", Title: "HTTP redirect", EnvVar: "ZANSKAR_HTTP_REDIRECT_ADDR", Value: set(cfg.RedirectAddr), Description: "Plain-HTTP listener that redirects to HTTPS."},
		{Key: "trust_proxy_tls", Title: "Trust proxy TLS", EnvVar: "ZANSKAR_TRUST_PROXY_TLS", Value: yesno(cfg.TrustProxyTLS), Description: "Cookies are marked Secure because TLS terminates in front."},
		{Key: "trusted_proxies", Title: "Trusted proxies", EnvVar: "ZANSKAR_TRUSTED_PROXIES", Value: strings.Join(proxies, ", "), Description: "Networks whose X-Forwarded-For is believed."},
		{Key: "allow_plain_http", Title: "Allow plain HTTP", EnvVar: "ZANSKAR_ALLOW_PLAIN_HTTP", Value: yesno(cfg.AllowPlainHTTP), Description: "Development only."},
		{Key: "db", Title: "Database", EnvVar: "ZANSKAR_DB_DRIVER, ZANSKAR_DB_DSN", Value: describeDSN(cfg.DBDriver, cfg.DBDSN), Description: "Where everything is stored."},
		masterKeySetting(cfg, keyVersion),
		{Key: "recordings_dir", Title: "Recordings directory", EnvVar: "ZANSKAR_RECORDINGS_DIR", Value: cfg.RecordingsDir, Description: "Local recording storage."},
		{Key: "recordings_s3", Title: "Recordings in S3", EnvVar: "ZANSKAR_RECORDINGS_S3_*", Value: set(cfg.RecordingsS3Bucket), Description: "Install-time bucket for recordings; the console's Settings page can override it."},
		{Key: "docker_path", Title: "Container runtime", EnvVar: "ZANSKAR_DOCKER_PATH", Value: map[bool]string{true: cfg.DockerPath, false: "docker (on PATH)"}[cfg.DockerPath != ""], Description: "Spawns database session containers."},
		{Key: "issuer", Title: "Authenticator issuer", EnvVar: "ZANSKAR_ISSUER", Value: cfg.Issuer, Description: "Name shown in authenticator apps; baked into enrolled authenticators."},
		{Key: "siem", Title: "SIEM export", EnvVar: "ZANSKAR_SIEM_*", Value: map[bool]string{true: "configured", false: "(not set)"}[cfg.SIEMSyslogAddr != "" || cfg.SIEMWebhookURL != ""], Description: "Where audit events are shipped."},
		{Key: "log_format", Title: "Log format", EnvVar: "ZANSKAR_LOG_FORMAT", Value: cfg.LogFormat, Description: "json or text."},
		{Key: "aws_gateway_principal", Title: "AWS gateway principal", EnvVar: "ZANSKAR_AWS_GATEWAY_PRINCIPAL", Value: set(cfg.AWSGatewayPrincipal), Description: "Override for the principal rendered into autoscaling trust policies; normally unset, the gateway detects it (see Autoscaling groups)."},
	}
}

// masterKeySetting says where the master key came from, never the key itself.
func masterKeySetting(cfg *config.Config, keyVersion int) settings.Boot {
	s := settings.Boot{Key: "master_key", Title: "Master key", EnvVar: "ZANSKAR_MASTER_KEY",
		Value:       fmt.Sprintf("set (data-key version %d active)", keyVersion),
		Description: "Wraps the data keys that seal every secret. Rotate with zanskar key rotate-master."}
	if cfg.MasterKeyFile != "" {
		s.EnvVar = "ZANSKAR_MASTER_KEY_FILE"
		s.Value = fmt.Sprintf("read from %s (data-key version %d active)", cfg.MasterKeyFile, keyVersion)
	}
	return s
}
