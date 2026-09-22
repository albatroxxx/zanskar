// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/target"
)

// TestDesktopParamsRDPPinsAtGateway checks the guacd parameters: the gateway
// verifies the certificate itself, so guacd is told to ignore it, and no
// cert-fingerprints pin is passed (it breaks IP-dialled self-signed certs).
func TestDesktopParamsRDPPinsAtGateway(t *testing.T) {
	fp := "abc123"
	tgt := &target.Target{Address: "10.0.0.5", Ports: map[target.Protocol]int{}, TLSFingerprint: &fp}
	p, err := desktopParams(tgt, target.RDP, nil, []byte("pw"), "Administrator", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Args["ignore-cert"] != "true" {
		t.Fatalf("ignore-cert = %q, want true", p.Args["ignore-cert"])
	}
	if _, ok := p.Args["cert-fingerprints"]; ok {
		t.Fatal("cert-fingerprints must not be sent to guacd")
	}
	if p.Args["security"] != "nla" {
		t.Fatalf("security = %q, want nla", p.Args["security"])
	}
	// An unprobed target (no pinned fingerprint) is refused, not trusted.
	if _, err := desktopParams(&target.Target{Address: "10.0.0.5", Ports: map[target.Protocol]int{}}, target.RDP, nil, []byte("pw"), "u", false, ""); err == nil {
		t.Fatal("RDP without a pinned certificate must be refused")
	}
}

// TestVerifyPinnedCert brings up a fake RDP TLS listener and checks that the
// gateway accepts the matching fingerprint and rejects anything else.
func TestVerifyPinnedCert(t *testing.T) {
	addr, fp := fakeRDPTLS(t)
	host, portStr, _ := net.SplitHostPort(addr)
	port := atoiOr(portStr, 3389)
	h := &Handler{Prober: &target.Prober{AllowLoopback: true}, DialTimeout: 3 * time.Second}

	match := &target.Target{Address: host, Ports: map[target.Protocol]int{target.RDP: port}, TLSFingerprint: &fp}
	if err := h.verifyPinnedCert(context.Background(), match); err != nil {
		t.Fatalf("matching fingerprint must pass: %v", err)
	}

	wrong := "0000000000000000000000000000000000000000000000000000000000000000"
	bad := &target.Target{Address: host, Ports: map[target.Protocol]int{target.RDP: port}, TLSFingerprint: &wrong}
	if err := h.verifyPinnedCert(context.Background(), bad); err == nil {
		t.Fatal("a different fingerprint must be rejected")
	}

	// Guard paths: no prober, and an unprobed target.
	if err := (&Handler{Prober: nil}).verifyPinnedCert(context.Background(), match); err == nil {
		t.Fatal("missing prober must error")
	}
	if err := h.verifyPinnedCert(context.Background(), &target.Target{Address: host, Ports: map[target.Protocol]int{target.RDP: port}}); err == nil {
		t.Fatal("target without a pinned fingerprint must error")
	}
}

// fakeRDPTLS listens, answers the RDP negotiation asking for TLS, completes a
// TLS handshake with a fresh self-signed certificate, and returns its address
// and the certificate's lowercase hex SHA-256 (the pin the prober computes).
func fakeRDPTLS(t *testing.T) (addr, fingerprint string) {
	t.Helper()
	cert, sum := selfSigned(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeRDP(conn, cert)
		}
	}()
	return ln.Addr().String(), hex.EncodeToString(sum[:])
}

func serveFakeRDP(conn net.Conn, cert tls.Certificate) {
	defer func() { _ = conn.Close() }()
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	length := int(hdr[2])<<8 | int(hdr[3])
	if length > 4 {
		if _, err := io.ReadFull(conn, make([]byte, length-4)); err != nil {
			return
		}
	}
	// TPKT + X.224 Connection Confirm + RDP_NEG_RSP selecting TLS (protocol 1).
	resp := []byte{
		0x03, 0x00, 0x00, 0x13,
		0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x08, 0x00,
		0x01, 0x00, 0x00, 0x00,
	}
	if _, err := conn.Write(resp); err != nil {
		return
	}
	srv := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
	_ = srv.Handshake()
	_ = srv.Close()
}

func selfSigned(t *testing.T) (tls.Certificate, [32]byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "EC2AMAZ-TEST"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert, sha256.Sum256(der)
}

func atoiOr(s string, def int) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if strings.TrimSpace(s) == "" {
		return def
	}
	return n
}
