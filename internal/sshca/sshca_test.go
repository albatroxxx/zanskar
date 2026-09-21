// SPDX-License-Identifier: Apache-2.0

package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// pemOf encodes a *pem.Block (what ssh.MarshalPrivateKey returns) to bytes.
func pemOf(block *pem.Block) []byte { return pem.EncodeToMemory(block) }

func TestIssueAndVerify(t *testing.T) {
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caBlock, err := ssh.MarshalPrivateKey(caPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pemOf(caBlock)

	s, err := NewSigner(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if s.AuthorityPublicKey() == "" {
		t.Fatal("authority public key empty")
	}

	userPub := freshUserKey(t)
	cert, err := s.Issue(userPub, CertParams{Principals: []string{"alice"}, KeyID: "zanskar:alice:1", Validity: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if cert.CertType != ssh.UserCert || cert.KeyId != "zanskar:alice:1" || cert.Serial == 0 {
		t.Fatalf("unexpected cert: type=%d keyid=%q serial=%d", cert.CertType, cert.KeyId, cert.Serial)
	}
	if _, ok := cert.Permissions.Extensions["permit-pty"]; !ok {
		t.Fatal("permit-pty missing")
	}
	for _, forbidden := range []string{"permit-port-forwarding", "permit-agent-forwarding", "permit-X11-forwarding", "permit-user-rc"} {
		if _, ok := cert.Permissions.Extensions[forbidden]; ok {
			t.Fatalf("least privilege violated: %s present", forbidden)
		}
	}
	window := int64(cert.ValidBefore) - int64(cert.ValidAfter)
	if window < int64((10*time.Minute).Seconds()) || window > int64((10*time.Minute+2*clockSkew).Seconds()) {
		t.Fatalf("validity window off: %d s", window)
	}

	// The certificate must verify against the CA for principal alice.
	checker := &ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool { return keyEqual(k, s.ca.PublicKey()) },
		Clock:           func() time.Time { return time.Now() },
	}
	if err := checker.CheckCert("alice", cert); err != nil {
		t.Fatalf("valid cert rejected: %v", err)
	}
	if err := checker.CheckCert("bob", cert); err == nil {
		t.Fatal("cert accepted for wrong principal")
	}
	// Expired certificate is rejected.
	expired := &ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool { return keyEqual(k, s.ca.PublicKey()) },
		Clock:           func() time.Time { return time.Now().Add(2 * time.Hour) },
	}
	if err := expired.CheckCert("alice", cert); err == nil {
		t.Fatal("expired cert accepted")
	}
}

func TestValidityClampAndPrincipals(t *testing.T) {
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caBlock, _ := ssh.MarshalPrivateKey(caPriv, "")
	s, err := NewSigner(pemOf(caBlock))
	if err != nil {
		t.Fatal(err)
	}
	up := freshUserKey(t)

	// Zero -> default.
	cert, err := s.Issue(up, CertParams{Principals: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	w := int64(cert.ValidBefore) - int64(cert.ValidAfter)
	if w < int64(DefaultValidity.Seconds()) || w > int64((DefaultValidity+2*clockSkew).Seconds()) {
		t.Fatalf("default validity off: %d", w)
	}
	// Over max rejected.
	if _, err := s.Issue(up, CertParams{Principals: []string{"a"}, Validity: MaxValidity + time.Minute}); !errors.Is(err, ErrValidityTooLong) {
		t.Fatalf("expected too-long error, got %v", err)
	}
	// Empty principals rejected.
	if _, err := s.Issue(up, CertParams{Principals: nil}); !errors.Is(err, ErrNoPrincipals) {
		t.Fatalf("expected no-principals error, got %v", err)
	}
	if _, err := s.Issue(up, CertParams{Principals: []string{"  "}}); !errors.Is(err, ErrNoPrincipals) {
		t.Fatalf("expected no-principals error for blank, got %v", err)
	}
	// Bad CA key.
	if _, err := NewSigner([]byte("not a key")); !errors.Is(err, ErrBadCAKey) {
		t.Fatalf("expected bad CA key error, got %v", err)
	}
}

func TestIssueForSession(t *testing.T) {
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caBlock, _ := ssh.MarshalPrivateKey(caPriv, "")
	caPEM := pemOf(caBlock)

	certLine, keyPEM, err := IssueForSession(caPEM, "operator", 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// The private key parses and matches the cert's key.
	signer, err := ssh.ParsePrivateKey([]byte(keyPEM))
	if err != nil {
		t.Fatalf("private key does not parse: %v", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certLine))
	if err != nil {
		t.Fatalf("cert does not parse: %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatal("not a certificate")
	}
	if !keyEqual(cert.Key, signer.PublicKey()) {
		t.Fatal("cert key does not match issued private key")
	}
	found := false
	for _, p := range cert.ValidPrincipals {
		if p == "operator" {
			found = true
		}
	}
	if !found {
		t.Fatalf("principal operator missing: %v", cert.ValidPrincipals)
	}
	// It verifies against the CA.
	s, _ := NewSigner(caPEM)
	checker := &ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool { return keyEqual(k, s.ca.PublicKey()) }}
	if err := checker.CheckCert("operator", cert); err != nil {
		t.Fatalf("session cert rejected: %v", err)
	}
}

func freshUserKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

func keyEqual(a, b ssh.PublicKey) bool {
	return string(a.Marshal()) == string(b.Marshal())
}
