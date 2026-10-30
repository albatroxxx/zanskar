// SPDX-License-Identifier: Apache-2.0

package tlscert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
)

// SourceACME is a certificate from an ACME CA, Let's Encrypt by default
// (ADR 0021, amended 2026-10-30).
const SourceACME = "acme"

// LetsEncrypt is the ACME directory used when the console names none.
const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// acmeBackoff is how long a name whose order failed waits before the next
// handshake may try again: a failing order on every handshake would run
// into the CA's rate limits.
const acmeBackoff = 10 * time.Minute

// ACME gets the gateway's certificate from an ACME CA when the console turns
// it on, so a managed-mode gateway needs no proxy in front to hold a
// public certificate. It answers TLS-ALPN-01 on the TLS listener and
// HTTP-01 on the redirect listener, orders only Names (a stranger's SNI can
// never make it order), keeps the account and certificates sealed in the
// database, and renews 30 days before the end.
type ACME struct {
	// Names it may order: the public URL's host and the DNS names among
	// the configured TLS hosts. Empty, it orders nothing.
	Names []string
	// Settings is read at each handshake: whether it is on, the account
	// email, and the directory URL.
	Settings func() (on bool, email, directory string)
	Cache    autocert.Cache
	// HTTPClient talks to the CA; nil is the default. Tests trust a test CA.
	HTTPClient *http.Client
	Log        *slog.Logger
	// Wait is how long a handshake waits for an order before it falls back;
	// zero is 10 seconds.
	Wait time.Duration

	mu       sync.Mutex
	mgr      *autocert.Manager
	built    string // email and directory mgr was built for
	ordering map[string]bool
	failed   map[string]time.Time
	lastErr  string
	lastLeaf *x509.Certificate
}

// NamesFor is what a gateway may order: the public URL's host and the DNS
// names among hosts, never an IP address, a bare word or localhost.
func NamesFor(publicHost string, hosts []string) []string {
	var out []string
	for _, h := range append([]string{publicHost}, hosts...) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || net.ParseIP(h) != nil || !strings.Contains(h, ".") || h == "localhost" || strings.HasSuffix(h, ".localhost") {
			continue
		}
		if ValidHost(h) == nil && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}

// On reports whether the console has it on and there is a name to order.
func (a *ACME) On() bool {
	if a == nil || a.Settings == nil || len(a.Names) == 0 {
		return false
	}
	on, _, _ := a.Settings()
	return on
}

// Covers reports whether name is one it may order.
func (a *ACME) Covers(name string) bool {
	return slices.Contains(a.Names, strings.ToLower(strings.TrimSuffix(name, ".")))
}

// manager returns the autocert manager for the current settings, built
// again when the email or the directory changed.
func (a *ACME) manager() *autocert.Manager {
	_, email, dir := a.Settings()
	if dir == "" {
		dir = LetsEncrypt
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mgr == nil || a.built != email+"\x00"+dir {
		a.mgr = &autocert.Manager{
			Prompt:      autocert.AcceptTOS,
			Email:       email,
			Cache:       a.Cache,
			HostPolicy:  autocert.HostWhitelist(a.Names...),
			RenewBefore: renewBefore,
			Client:      &acme.Client{DirectoryURL: dir, HTTPClient: a.HTTPClient},
		}
		a.built = email + "\x00" + dir
	}
	return a.mgr
}

// GetCertificate answers a handshake: a TLS-ALPN-01 challenge, or the
// certificate for a covered name, ordering it when there is none. An order
// runs in the background and a handshake waits for it at most Wait, then
// falls back: autocert allows an order five minutes, and the ACME client
// retries while a CA answers 503, so a CA outage would otherwise hold every
// handshake for minutes. One order per name runs at a time, and a name
// whose order failed is not tried again for acmeBackoff.
func (a *ACME) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	mgr := a.manager()
	if challenge(hello) {
		return mgr.GetCertificate(hello)
	}
	name := strings.ToLower(hello.ServerName)
	a.mu.Lock()
	if at, failed := a.failed[name]; failed && time.Since(at) < acmeBackoff {
		a.mu.Unlock()
		return nil, errors.New("tlscert: acme order failed recently; waiting before the next")
	}
	if a.ordering[name] {
		a.mu.Unlock()
		return nil, errors.New("tlscert: acme order in progress")
	}
	if a.ordering == nil {
		a.ordering = map[string]bool{}
	}
	a.ordering[name] = true
	a.mu.Unlock()

	done := make(chan struct{})
	var cert *tls.Certificate
	var err error
	go func() {
		defer close(done)
		cert, err = mgr.GetCertificate(hello)
		a.settle(name, cert, err)
	}()
	wait := a.Wait
	if wait <= 0 {
		wait = 10 * time.Second
	}
	select {
	case <-done:
		return cert, err
	case <-time.After(wait):
		return nil, errors.New("tlscert: acme order in progress")
	}
}

// settle records how an order for name ended.
func (a *ACME) settle(name string, cert *tls.Certificate, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.ordering, name)
	if err != nil {
		if a.failed == nil {
			a.failed = map[string]time.Time{}
		}
		a.failed[name] = time.Now()
		a.lastErr = err.Error()
		if a.Log != nil {
			a.Log.Warn("ACME certificate not obtained; serving the next certificate", "name", name, "err", err)
		}
		return
	}
	delete(a.failed, name)
	a.lastErr = ""
	if cert.Leaf != nil {
		a.lastLeaf = cert.Leaf
	} else if leaf, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil {
		a.lastLeaf = leaf
	}
}

// HTTPHandler answers HTTP-01 challenges on the redirect listener and hands
// every other request to fallback; off, it is fallback.
func (a *ACME) HTTPHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.On() && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			a.manager().HTTPHandler(fallback).ServeHTTP(w, r)
			return
		}
		fallback.ServeHTTP(w, r)
	})
}

// ACMEStatus is what the Settings card shows.
type ACMEStatus struct {
	On        bool      `json:"on"`
	Names     []string  `json:"names"`
	NotAfter  time.Time `json:"not_after,omitzero"`
	Issuer    string    `json:"issuer,omitempty"`
	LastError string    `json:"last_error,omitempty"`
}

// Status describes it for the console.
func (a *ACME) Status() ACMEStatus {
	if a == nil {
		return ACMEStatus{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	st := ACMEStatus{Names: a.Names, LastError: a.lastErr}
	if a.Settings != nil && len(a.Names) > 0 {
		st.On, _, _ = a.Settings()
	}
	if a.lastLeaf != nil {
		st.NotAfter, st.Issuer = a.lastLeaf.NotAfter, a.lastLeaf.Issuer.CommonName
	}
	return st
}

// challenge reports whether the handshake is a TLS-ALPN-01 validation.
func challenge(hello *tls.ClientHelloInfo) bool {
	return len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acme.ALPNProto
}

// DBCache keeps autocert's account key and certificates in acme_cache,
// sealed like an uploaded certificate's key, so a second gateway on the
// same database reuses them instead of ordering again.
type DBCache struct{ Repo *Repo }

// cacheTable is the AAD's table for the cache's sealed rows.
const cacheTable = "acme_cache"

// Get implements autocert.Cache.
func (c DBCache) Get(ctx context.Context, key string) ([]byte, error) {
	var sealed []byte
	var ver int
	err := c.Repo.db.QueryRowContext(ctx, c.Repo.db.Rebind(`SELECT data_enc, key_version FROM acme_cache WHERE cache_key = ?`), key).Scan(&sealed, &ver)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, err
	}
	return c.Repo.ring.Decrypt(keyring.AAD(cacheTable, key), sealed, ver)
}

// Put implements autocert.Cache.
func (c DBCache) Put(ctx context.Context, key string, data []byte) error {
	sealed, ver, err := c.Repo.ring.Encrypt(keyring.AAD(cacheTable, key), data)
	if err != nil {
		return err
	}
	_, err = c.Repo.db.ExecContext(ctx, c.Repo.db.Rebind(`INSERT INTO acme_cache (cache_key, data_enc, key_version, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (cache_key) DO UPDATE SET data_enc = excluded.data_enc, key_version = excluded.key_version, updated_at = excluded.updated_at`),
		key, sealed, ver, store.TimeArg(time.Now().UTC()))
	return err
}

// Delete implements autocert.Cache.
func (c DBCache) Delete(ctx context.Context, key string) error {
	_, err := c.Repo.db.ExecContext(ctx, c.Repo.db.Rebind(`DELETE FROM acme_cache WHERE cache_key = ?`), key)
	return err
}
