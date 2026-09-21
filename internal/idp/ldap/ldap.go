// SPDX-License-Identifier: Apache-2.0

// Package ldap authenticates users against an LDAP or Active Directory
// server with the bind-and-search pattern: a service account finds the user's
// entry, the user's password is verified by binding as that entry, and group
// membership is read from memberOf or a group search.
package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/albatroxxx/zanskar/internal/idp"
)

// Errors. Callers must present ErrInvalidCredentials identically for an
// unknown user and a wrong password.
var (
	ErrInvalidCredentials = errors.New("ldap: invalid credentials")
	ErrDirectory          = errors.New("ldap: directory unavailable")
	ErrConfig             = errors.New("ldap: invalid configuration")
)

// Authenticator verifies passwords against a directory.
type Authenticator struct {
	// Timeout bounds the connection and each operation. Zero means 10 s.
	Timeout time.Duration
}

func (a *Authenticator) timeout() time.Duration {
	if a.Timeout <= 0 {
		return 10 * time.Second
	}
	return a.Timeout
}

// Authenticate verifies username/password and returns the asserted identity.
func (a *Authenticator) Authenticate(ctx context.Context, cfg *idp.LDAPConfig, username, password string) (*idp.Identity, error) {
	// Empty and whitespace-only passwords are refused before any network
	// call: directories treat an empty simple bind as anonymous and succeed.
	if strings.TrimSpace(password) == "" || strings.TrimSpace(username) == "" {
		return nil, ErrInvalidCredentials
	}
	conn, err := a.connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("%w: service bind: %v", ErrDirectory, redact(err))
	}

	entry, err := a.findUser(cfg, conn, username)
	if err != nil {
		return nil, err
	}
	// Verify the password by binding as the user; never log it.
	if err := conn.Bind(entry.DN, password); err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultInvalidCredentials) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("%w: user bind: %v", ErrDirectory, redact(err))
	}
	// Back to the service account for group lookups.
	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("%w: service rebind: %v", ErrDirectory, redact(err))
	}

	groups, err := a.groups(cfg, conn, entry)
	if err != nil {
		return nil, err
	}
	id := &idp.Identity{
		ExternalID:  externalID(entry),
		Username:    strings.ToLower(entry.GetAttributeValue(cfg.UsernameAttr)),
		DisplayName: entry.GetAttributeValue(cfg.DisplayNameAttr),
		Email:       strings.ToLower(entry.GetAttributeValue(cfg.EmailAttr)),
		Groups:      groups,
	}
	if id.Username == "" {
		return nil, fmt.Errorf("%w: entry has no %s attribute", ErrConfig, cfg.UsernameAttr)
	}
	return id, nil
}

// Test connects, binds as the service account and runs the user search with
// a placeholder value, so an admin learns about bad URLs, certificates,
// credentials and filters before enabling the provider.
func (a *Authenticator) Test(ctx context.Context, cfg *idp.LDAPConfig) error {
	conn, err := a.connect(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		return fmt.Errorf("%w: service bind: %v", ErrDirectory, redact(err))
	}
	req := goldap.NewSearchRequest(cfg.BaseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 1, int(a.timeout().Seconds()), false,
		fmt.Sprintf(cfg.UserFilter, goldap.EscapeFilter("zanskar-connectivity-test")), []string{"1.1"}, nil)
	if _, err := conn.Search(req); err != nil && !goldap.IsErrorWithCode(err, goldap.LDAPResultSizeLimitExceeded) {
		return fmt.Errorf("%w: user search: %v", ErrConfig, redact(err))
	}
	return nil
}

func (a *Authenticator) connect(ctx context.Context, cfg *idp.LDAPConfig) (*goldap.Conn, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "ldaps" && u.Scheme != "ldap") {
		return nil, fmt.Errorf("%w: url", ErrConfig)
	}
	tlsCfg, err := tlsConfig(cfg, u.Hostname())
	if err != nil {
		return nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, a.timeout())
	defer cancel()
	opts := []goldap.DialOpt{}
	if u.Scheme == "ldaps" {
		opts = append(opts, goldap.DialWithTLSConfig(tlsCfg))
	}
	conn, err := goldap.DialURL(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDirectory, redact(err))
	}
	conn.SetTimeout(a.timeout())
	if u.Scheme == "ldap" {
		if !cfg.StartTLS {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: plain ldap requires start_tls", ErrConfig)
		}
		if err := conn.StartTLS(tlsCfg); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: starttls: %v", ErrDirectory, redact(err))
		}
	}
	_ = dctx
	return conn, nil
}

func tlsConfig(cfg *idp.LDAPConfig, host string) (*tls.Config, error) {
	tc := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if cfg.InsecureSkipVerify {
		tc.InsecureSkipVerify = true // #nosec G402 -- explicit development-only opt-in
		return tc, nil
	}
	if strings.TrimSpace(cfg.CACertPEM) == "" {
		return nil, fmt.Errorf("%w: ca_cert_pem required", ErrConfig)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(cfg.CACertPEM)) {
		return nil, fmt.Errorf("%w: ca_cert_pem has no certificates", ErrConfig)
	}
	tc.RootCAs = pool
	return tc, nil
}

func (a *Authenticator) findUser(cfg *idp.LDAPConfig, conn *goldap.Conn, username string) (*goldap.Entry, error) {
	candidates := []string{username}
	if cfg.UsernameSuffix != "" && !strings.Contains(username, "@") {
		candidates = append(candidates, username+cfg.UsernameSuffix)
	}
	attrs := []string{cfg.UsernameAttr, cfg.DisplayNameAttr, cfg.EmailAttr, "objectGUID", "entryUUID"}
	if cfg.GroupAttr != "" {
		attrs = append(attrs, cfg.GroupAttr)
	}
	for _, c := range candidates {
		req := goldap.NewSearchRequest(cfg.BaseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 2, int(a.timeout().Seconds()), false,
			fmt.Sprintf(cfg.UserFilter, goldap.EscapeFilter(c)), attrs, nil)
		res, err := conn.Search(req)
		if err != nil {
			return nil, fmt.Errorf("%w: user search: %v", ErrDirectory, redact(err))
		}
		switch len(res.Entries) {
		case 0:
			continue
		case 1:
			return res.Entries[0], nil
		default:
			// Ambiguous filter: refuse rather than guess.
			return nil, ErrInvalidCredentials
		}
	}
	return nil, ErrInvalidCredentials
}

func (a *Authenticator) groups(cfg *idp.LDAPConfig, conn *goldap.Conn, entry *goldap.Entry) ([]string, error) {
	if cfg.GroupAttr != "" {
		var out []string
		for _, dn := range entry.GetAttributeValues(cfg.GroupAttr) {
			if name := firstRDNValue(dn); name != "" {
				out = append(out, name)
			}
		}
		return out, nil
	}
	if cfg.GroupBaseDN == "" || cfg.GroupFilter == "" {
		return nil, nil
	}
	nameAttr := cfg.GroupNameAttr
	if nameAttr == "" {
		nameAttr = "cn"
	}
	req := goldap.NewSearchRequest(cfg.GroupBaseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, int(a.timeout().Seconds()), false,
		fmt.Sprintf(cfg.GroupFilter, goldap.EscapeFilter(entry.DN)), []string{nameAttr}, nil)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("%w: group search: %v", ErrDirectory, redact(err))
	}
	var out []string
	for _, g := range res.Entries {
		if v := g.GetAttributeValue(nameAttr); v != "" {
			out = append(out, v)
		} else if name := firstRDNValue(g.DN); name != "" {
			out = append(out, name)
		}
	}
	return out, nil
}

// externalID picks the most stable identifier the directory offers.
func externalID(entry *goldap.Entry) string {
	if raw := entry.GetRawAttributeValue("objectGUID"); len(raw) == 16 {
		return "guid:" + formatObjectGUID(raw)
	}
	if v := entry.GetAttributeValue("entryUUID"); v != "" {
		return "uuid:" + strings.ToLower(v)
	}
	return "dn:" + strings.ToLower(entry.DN)
}

// formatObjectGUID renders Active Directory's mixed-endian objectGUID bytes
// as the canonical text form AD tools display.
func formatObjectGUID(b []byte) string {
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// firstRDNValue returns the value of the first RDN of a DN ("cn=ops,ou=..." → "ops").
func firstRDNValue(dn string) string {
	parsed, err := goldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
		return ""
	}
	return parsed.RDNs[0].Attributes[0].Value
}

// redact strips anything that could echo a password from an error message.
func redact(err error) string {
	msg := err.Error()
	if i := strings.Index(strings.ToLower(msg), "password"); i >= 0 {
		return msg[:i] + "password [redacted]"
	}
	return msg
}
