// SPDX-License-Identifier: Apache-2.0

package credential

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// A cluster credential (ADR 0045) is Zanskar's own identity in the cluster:
// a service account's token, sealed as the password, or a client
// certificate with its key, sealed as one PEM text. Neither names a user,
// and the gateway never shows either back.
func TestKubernetesCredentials(t *testing.T) {
	v, _ := testVault(t)
	ctx := context.Background()

	tok := &Credential{Name: "sa", Type: TypeKubeToken, Mode: ModeVaulted, Username: "ignored"}
	if err := v.Create(ctx, tok, &Secret{Password: "not-a-real-token-just-letters"}, ""); err != nil || !tok.HasSecret || tok.Username != "" {
		t.Fatalf("token: %v %+v", err, tok)
	}
	o, err := v.Open(ctx, tok.ID)
	if err != nil || o.Password != "not-a-real-token-just-letters" {
		t.Fatalf("open token: %v %q", err, o.Password)
	}
	for name, s := range map[string]*Secret{
		"no token":           {},
		"a token with space": {Password: "abc def"},
		"a key as well":      {Password: "abc", PrivateKey: "x"},
	} {
		if err := v.Create(ctx, &Credential{Name: name, Type: TypeKubeToken, Mode: ModeVaulted}, s, ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v", name, err)
		}
	}

	certPEM := selfSignedClientPEM(t)
	cc := &Credential{Name: "cert", Type: TypeKubeClientCert, Mode: ModeVaulted}
	if err := v.Create(ctx, cc, &Secret{PrivateKey: certPEM}, ""); err != nil || !cc.HasSecret || cc.PublicKey != "" {
		t.Fatalf("client cert: %v %+v", err, cc)
	}
	if o, err := v.Open(ctx, cc.ID); err != nil || string(o.PrivateKey) != certPEM {
		t.Fatalf("open client cert: %v", err)
	}
	keyAt := strings.Index(certPEM, "-----BEGIN EC PRIVATE KEY-----")
	if keyAt < 0 {
		t.Fatal("the test PEM holds no key")
	}
	keyOnly := certPEM[keyAt:]
	for name, s := range map[string]*Secret{
		"nothing":            {},
		"a password":         {Password: "x"},
		"a key with no cert": {PrivateKey: keyOnly},
		"not pem":            {PrivateKey: "hello"},
	} {
		if err := v.Create(ctx, &Credential{Name: name, Type: TypeKubeClientCert, Mode: ModeVaulted}, s, ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// Neither is offered user-supplied: the cluster's credential is
	// Zanskar's, never the person's.
	for _, typ := range []Type{TypeKubeToken, TypeKubeClientCert} {
		if err := v.Create(ctx, &Credential{Name: "ask-" + string(typ), Type: typ, Mode: ModeUserSupplied}, nil, ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s user-supplied: got %v", typ, err)
		}
	}
}

// selfSignedClientPEM makes a certificate and its key, as kubectl's
// client-certificate-data and client-key-data read decoded and joined.
func selfSignedClientPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "zanskar"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}
