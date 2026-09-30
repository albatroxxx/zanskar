// SPDX-License-Identifier: Apache-2.0

// Package tlscert manages the certificate the gateway serves (ADR 0021).
// The certificate an administrator uploads in the console wins, else the
// one named in the environment file, else a self-signed one generated at
// first start so a fresh install speaks HTTPS before anyone has a
// certificate to give it. The active certificate is swapped in place: the
// listener asks for it on every handshake, so an upload applies to the next
// connection with no restart. Private keys are sealed by the key ring like
// every other secret and never leave this package.
package tlscert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
)

// Sources of the active certificate, in precedence order.
const (
	SourceUploaded  = "uploaded"  // set in the console
	SourceFile      = "file"      // ZANSKAR_TLS_CERT / ZANSKAR_TLS_KEY
	SourceGenerated = "generated" // self-signed, made by the gateway
)

const table = "tls_certificates"

// Errors.
var (
	ErrInvalid  = errors.New("tlscert: invalid certificate")
	ErrNotFound = errors.New("tlscert: not found")
)

// Info describes a certificate without its key.
type Info struct {
	Source      string    `json:"source"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Hosts       []string  `json:"hosts"` // DNS names and IPs
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"` // SHA-256 of the leaf, hex
	SelfSigned  bool      `json:"self_signed"`
	CertPEM     string    `json:"cert_pem,omitempty"`
}

// ExpiresWithin reports whether the certificate ends before now+d.
func (i Info) ExpiresWithin(d time.Duration) bool { return time.Now().Add(d).After(i.NotAfter) }

// missingHosts lists the wanted names the certificate does not carry. Name
// comparison is case-insensitive; an address is compared as an address, so
// 10.0.0.7 and 10.00.0.7 are not two different things.
func missingHosts(leaf *x509.Certificate, want []string) []string {
	var missing []string
	for _, w := range want {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		found := false
		if ip := net.ParseIP(w); ip != nil {
			for _, have := range leaf.IPAddresses {
				if have.Equal(ip) {
					found = true
					break
				}
			}
		} else {
			for _, have := range leaf.DNSNames {
				if strings.EqualFold(have, w) {
					found = true
					break
				}
			}
		}
		if !found {
			missing = append(missing, w)
		}
	}
	return missing
}

func describe(source string, leaf *x509.Certificate, certPEM string) Info {
	sum := sha256.Sum256(leaf.Raw)
	hosts := append([]string(nil), leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		hosts = append(hosts, ip.String())
	}
	sort.Strings(hosts)
	return Info{
		Source: source, Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(), Hosts: hosts,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Fingerprint: hex.EncodeToString(sum[:]),
		SelfSigned: leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil,
		CertPEM:    certPEM,
	}
}

// Parse checks a PEM certificate chain and key: they must match, the leaf
// must be in its validity period and, when it lists extended key usages,
// allow server authentication. An encrypted key is refused with a message
// that says so.
func Parse(certPEM, keyPEM string) (tls.Certificate, *x509.Certificate, error) {
	if b, _ := pem.Decode([]byte(keyPEM)); b != nil && (strings.Contains(b.Type, "ENCRYPTED") || b.Headers["Proc-Type"] != "") {
		return tls.Certificate{}, nil, fmt.Errorf("%w: the private key is encrypted; decrypt it first (openssl pkey -in key.pem -out plain.pem)", ErrInvalid)
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	now := time.Now()
	if now.After(leaf.NotAfter) {
		return tls.Certificate{}, nil, fmt.Errorf("%w: the certificate expired on %s", ErrInvalid, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if now.Before(leaf.NotBefore) {
		return tls.Certificate{}, nil, fmt.Errorf("%w: the certificate is not valid before %s", ErrInvalid, leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if len(leaf.ExtKeyUsage) > 0 {
		ok := false
		for _, u := range leaf.ExtKeyUsage {
			if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
				ok = true
			}
		}
		if !ok {
			return tls.Certificate{}, nil, fmt.Errorf("%w: the certificate does not allow server authentication", ErrInvalid)
		}
	}
	cert.Leaf = leaf
	return cert, leaf, nil
}

// SelfSign makes a certificate for hosts (DNS names and IP addresses),
// valid from now for two years, with a fresh P-256 key.
func SelfSign(hosts []string) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Zanskar gateway", Organization: []string{"Zanskar self-signed"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range dedupe(hosts) {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if err := ValidHost(h); err != nil {
			return "", "", err
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, strings.ToLower(h))
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), nil
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$`)

// ValidHost accepts an IP address or a DNS name of at most 253 characters.
func ValidHost(h string) error {
	if net.ParseIP(h) != nil {
		return nil
	}
	if len(h) > 253 || !hostRe.MatchString(h) {
		return fmt.Errorf("%w: %q is not a host name or IP address", ErrInvalid, h)
	}
	return nil
}

// LocalHosts guesses the names a self-signed certificate should carry: the
// listen host when it is a real address, the machine's host name, every
// non-loopback interface address when bound to all interfaces, and
// localhost for the operator's own checks. extra is added first, for names
// the machine cannot work out: a cloud instance's public address is
// translated upstream and never appears on an interface, so it has to be
// supplied (ZANSKAR_TLS_HOSTS, or `zanskar init -tls-hosts`).
func LocalHosts(listenAddr string, extra ...string) []string {
	hosts := append([]string{}, extra...)
	hosts = append(hosts, "localhost", "127.0.0.1")
	if hn, err := os.Hostname(); err == nil && hn != "" {
		hosts = append(hosts, hn)
	}
	host, _, _ := net.SplitHostPort(listenAddr)
	switch host {
	case "", "0.0.0.0", "::":
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
					hosts = append(hosts, ipn.IP.String())
				}
			}
		}
	default:
		hosts = append(hosts, host)
	}
	return dedupe(hosts)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range in {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// Repo stores the two managed rows.
type Repo struct {
	db   *store.DB
	ring *keyring.Ring
}

// NewRepo returns a repository over db sealing keys with ring.
func NewRepo(db *store.DB, ring *keyring.Ring) *Repo { return &Repo{db: db, ring: ring} }

// Get returns the certificate and key of kind, or ErrNotFound.
func (r *Repo) Get(ctx context.Context, kind string) (certPEM, keyPEM string, err error) {
	var sealed []byte
	var ver int
	err = r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT cert_pem, key_enc, key_version FROM tls_certificates WHERE kind = ?`), kind).Scan(&certPEM, &sealed, &ver)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", err
	}
	plain, err := r.ring.Decrypt(keyring.AAD(table, kind), sealed, ver)
	if err != nil {
		return "", "", fmt.Errorf("tlscert: unseal %s key: %w", kind, err)
	}
	return certPEM, string(plain), nil
}

// Put stores (or replaces) the row of kind.
func (r *Repo) Put(ctx context.Context, kind, certPEM, keyPEM, createdBy string) error {
	sealed, ver, err := r.ring.Encrypt(keyring.AAD(table, kind), []byte(keyPEM))
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO tls_certificates (kind, cert_pem, key_enc, key_version, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (kind) DO UPDATE SET cert_pem = excluded.cert_pem, key_enc = excluded.key_enc, key_version = excluded.key_version, created_by = excluded.created_by, created_at = excluded.created_at`),
		kind, certPEM, sealed, ver, sql.NullString{String: createdBy, Valid: createdBy != ""}, store.TimeArg(time.Now().UTC()))
	return err
}

// Delete removes the row of kind.
func (r *Repo) Delete(ctx context.Context, kind string) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM tls_certificates WHERE kind = ?`), kind)
	return err
}

// Manager resolves the active certificate and hands it to the listener.
type Manager struct {
	Repo *Repo
	Log  *slog.Logger
	// File is the certificate from the environment, when there is one.
	File *tls.Certificate
	// Hosts are the names a generated certificate carries.
	Hosts []string

	active atomic.Pointer[entry]
}

type entry struct {
	cert tls.Certificate
	info Info
}

// Load resolves the active certificate: uploaded, else file, else a
// generated one, made now when there is none or it is within thirty days
// of its end.
func (m *Manager) Load(ctx context.Context) error {
	if m.Log == nil {
		m.Log = slog.Default()
	}
	if certPEM, keyPEM, err := m.Repo.Get(ctx, SourceUploaded); err == nil {
		cert, leaf, perr := Parse(certPEM, keyPEM)
		if perr == nil {
			m.set(SourceUploaded, cert, leaf, certPEM)
			return nil
		}
		// An upload that expired while the gateway was down would hide from
		// the card and could never be removed; drop it and say so.
		m.Log.Warn("uploaded TLS certificate no longer valid; removed, falling back", "err", perr)
		if err := m.Repo.Delete(ctx, SourceUploaded); err != nil {
			return err
		}
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	if m.File != nil {
		leaf := m.File.Leaf
		if leaf == nil {
			var err error
			if leaf, err = x509.ParseCertificate(m.File.Certificate[0]); err != nil {
				return err
			}
		}
		m.set(SourceFile, *m.File, leaf, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})))
		return nil
	}
	certPEM, keyPEM, err := m.Repo.Get(ctx, SourceGenerated)
	if err == nil {
		if cert, leaf, perr := Parse(certPEM, keyPEM); perr == nil && time.Now().Add(30*24*time.Hour).Before(leaf.NotAfter) {
			// A name added to the configuration after the first start has to
			// take effect, or the operator sets ZANSKAR_TLS_HOSTS, restarts,
			// and nothing happens.
			if missing := missingHosts(leaf, m.Hosts); len(missing) > 0 {
				m.Log.Info("regenerating the self-signed certificate for newly configured names", "names", missing)
			} else {
				m.set(SourceGenerated, cert, leaf, certPEM)
				return nil
			}
		}
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	// Nothing uploaded and no file certificate applies, or the two branches
	// above would have returned, so a generated certificate is what serves.
	// Clear the previous one first: Regenerate leaves an uploaded or file
	// certificate in place, and after Reset the uploaded one is still the
	// active entry even though its row is gone.
	m.active.Store(nil)
	return m.Regenerate(ctx, m.Hosts, "")
}

func (m *Manager) set(source string, cert tls.Certificate, leaf *x509.Certificate, certPEM string) {
	m.active.Store(&entry{cert: cert, info: describe(source, leaf, certPEM)})
}

// GetCertificate is what the listener's tls.Config calls per handshake.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	e := m.active.Load()
	if e == nil {
		return nil, errors.New("tlscert: no certificate loaded")
	}
	return &e.cert, nil
}

// Active describes the certificate being served.
func (m *Manager) Active() Info {
	if e := m.active.Load(); e != nil {
		return e.info
	}
	return Info{}
}

// Upload validates, stores and serves an administrator's certificate.
func (m *Manager) Upload(ctx context.Context, certPEM, keyPEM, by string) (Info, error) {
	cert, leaf, err := Parse(certPEM, keyPEM)
	if err != nil {
		return Info{}, err
	}
	if err := m.Repo.Put(ctx, SourceUploaded, certPEM, keyPEM, by); err != nil {
		return Info{}, err
	}
	m.set(SourceUploaded, cert, leaf, certPEM)
	return m.Active(), nil
}

// Reset removes the uploaded certificate; the file or a generated one
// serves again.
func (m *Manager) Reset(ctx context.Context) (Info, error) {
	if err := m.Repo.Delete(ctx, SourceUploaded); err != nil {
		return Info{}, err
	}
	if err := m.Load(ctx); err != nil {
		return Info{}, err
	}
	return m.Active(), nil
}

// Regenerate makes a new self-signed certificate for hosts and serves it
// unless an uploaded or file certificate takes precedence.
func (m *Manager) Regenerate(ctx context.Context, hosts []string, by string) error {
	if len(hosts) == 0 {
		hosts = []string{"localhost"}
	}
	certPEM, keyPEM, err := SelfSign(hosts)
	if err != nil {
		return err
	}
	if err := m.Repo.Put(ctx, SourceGenerated, certPEM, keyPEM, by); err != nil {
		return err
	}
	if e := m.active.Load(); e != nil && e.info.Source != SourceGenerated {
		return nil
	}
	cert, leaf, err := Parse(certPEM, keyPEM)
	if err != nil {
		return err
	}
	m.set(SourceGenerated, cert, leaf, certPEM)
	// The names came from an administrator's request; the fingerprint and
	// count identify the certificate without echoing them into the log.
	m.Log.Info("serving a self-signed TLS certificate; upload a real one in Settings", "host_count", len(hosts), "sha256", m.Active().Fingerprint)
	return nil
}

// Generated describes the stored self-signed certificate, if any.
func (m *Manager) Generated(ctx context.Context) (Info, error) {
	certPEM, keyPEM, err := m.Repo.Get(ctx, SourceGenerated)
	if err != nil {
		return Info{}, err
	}
	_, leaf, err := Parse(certPEM, keyPEM)
	if err != nil {
		return Info{}, err
	}
	return describe(SourceGenerated, leaf, certPEM), nil
}

// Uploaded describes the stored uploaded certificate, if any.
func (m *Manager) Uploaded(ctx context.Context) (Info, error) {
	certPEM, keyPEM, err := m.Repo.Get(ctx, SourceUploaded)
	if err != nil {
		return Info{}, err
	}
	_, leaf, err := Parse(certPEM, keyPEM)
	if err != nil {
		return Info{}, err
	}
	return describe(SourceUploaded, leaf, certPEM), nil
}
