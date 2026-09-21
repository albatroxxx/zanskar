// SPDX-License-Identifier: Apache-2.0

// Package sshca mints short-lived SSH user certificates from a certificate
// authority key (ADR 0005). Instead of storing a private key per target,
// Zanskar signs a fresh, minutes-long certificate at connect time. An admin
// installs the authority's public key once in each host's TrustedUserCAKeys,
// and the gateway holds no long-lived user key material.
package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/albatroxxx/zanskar/internal/crypto"
)

// Default and maximum lifetime for an issued certificate. Certificates are
// meant to live only for the length of a connect handshake, so the window is
// deliberately narrow.
const (
	DefaultValidity = 5 * time.Minute
	MaxValidity     = time.Hour
	// clockSkew backdates ValidAfter so a target whose clock runs slightly
	// ahead still accepts a freshly minted certificate.
	clockSkew = 60 * time.Second
)

// Errors.
var (
	ErrBadCAKey        = errors.New("sshca: invalid CA private key")
	ErrNoPrincipals    = errors.New("sshca: at least one principal is required")
	ErrValidityTooLong = errors.New("sshca: validity exceeds the maximum")
)

// Signer wraps a CA private key and issues user certificates.
type Signer struct {
	ca ssh.Signer
}

// NewSigner parses a CA private key in PEM form (the sealed secret of an
// ssh_ca credential) and returns a Signer.
func NewSigner(caPrivatePEM []byte) (*Signer, error) {
	ca, err := ssh.ParsePrivateKey(caPrivatePEM)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadCAKey, err)
	}
	return &Signer{ca: ca}, nil
}

// AuthorityPublicKey returns the CA public key in authorized_keys format.
// This is the value an admin installs in a host's TrustedUserCAKeys file so
// the host trusts certificates this Signer issues.
func (s *Signer) AuthorityPublicKey() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.ca.PublicKey())))
}

// CertParams describes the certificate to mint.
type CertParams struct {
	// Principals are the login names the certificate is valid for. Required.
	Principals []string
	// Validity is the lifetime from now. Zero uses DefaultValidity; values
	// above MaxValidity are rejected.
	Validity time.Duration
	// KeyID is recorded in the certificate and logged by the target's sshd,
	// so it should identify the session (e.g. "zanskar:alice:1700000000").
	KeyID string
	// SourceAddress, when set, pins the certificate to a client CIDR or IP
	// via the source-address critical option.
	SourceAddress string
	// Extensions are added on top of the least-privilege default of
	// permit-pty only. Values are usually empty strings.
	Extensions map[string]string
}

// Issue signs a user certificate for userPub. The certificate grants only a
// PTY by default; port, agent, X11 forwarding and user-rc are withheld unless
// the caller adds them explicitly through Extensions.
func (s *Signer) Issue(userPub ssh.PublicKey, p CertParams) (*ssh.Certificate, error) {
	if len(p.Principals) == 0 {
		return nil, ErrNoPrincipals
	}
	for _, pr := range p.Principals {
		if strings.TrimSpace(pr) == "" {
			return nil, ErrNoPrincipals
		}
	}
	validity := p.Validity
	if validity <= 0 {
		validity = DefaultValidity
	}
	if validity > MaxValidity {
		return nil, fmt.Errorf("%w: %s > %s", ErrValidityTooLong, validity, MaxValidity)
	}

	serial, err := randUint64()
	if err != nil {
		return nil, err
	}

	extensions := map[string]string{"permit-pty": ""}
	for k, v := range p.Extensions {
		extensions[k] = v
	}

	criticalOptions := map[string]string{}
	if p.SourceAddress != "" {
		criticalOptions["source-address"] = p.SourceAddress
	}

	now := time.Now()
	cert := &ssh.Certificate{
		Key:             userPub,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           p.KeyID,
		ValidPrincipals: p.Principals,
		ValidAfter:      uint64(now.Add(-clockSkew).Unix()), // #nosec G115 -- unix seconds fit uint64
		ValidBefore:     uint64(now.Add(validity).Unix()),   // #nosec G115 -- unix seconds fit uint64
		Permissions: ssh.Permissions{
			CriticalOptions: criticalOptions,
			Extensions:      extensions,
		},
	}
	if err := cert.SignCert(rand.Reader, s.ca); err != nil {
		return nil, fmt.Errorf("sshca: sign: %w", err)
	}
	return cert, nil
}

// IssueForSession generates a throwaway ed25519 user key, signs a certificate
// for loginUser, and returns the certificate in authorized_keys form together
// with the private key in OpenSSH PEM form. The gateway hands both to the SSH
// client and keeps neither: the key never touches disk or the database.
func IssueForSession(caPrivatePEM []byte, loginUser string, validity time.Duration) (certAuthorizedKey string, privateKeyPEM string, err error) {
	signer, err := NewSigner(caPrivatePEM)
	if err != nil {
		return "", "", err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	// The private key is copied into the marshaled PEM below; scrub the
	// original once we are done with it.
	defer crypto.Zero(priv)

	userSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("sshca: user key: %w", err)
	}
	_ = pub

	cert, err := signer.Issue(userSigner.PublicKey(), CertParams{
		Principals: []string{loginUser},
		Validity:   validity,
		KeyID:      fmt.Sprintf("zanskar:%s:%d", loginUser, time.Now().Unix()),
	})
	if err != nil {
		return "", "", err
	}

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return "", "", fmt.Errorf("sshca: marshal user key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(block)

	certLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
	return certLine, string(pemBytes), nil
}

func randUint64() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("sshca: serial: %w", err)
	}
	return binary.BigEndian.Uint64(b[:]), nil
}
