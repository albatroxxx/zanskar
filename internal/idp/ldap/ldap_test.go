// SPDX-License-Identifier: Apache-2.0

package ldap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"

	"github.com/albatroxxx/zanskar/internal/idp"
)

const (
	svcDN     = "cn=svc,dc=example,dc=com"
	svcPW     = "svcpw"
	aliceDN   = "uid=alice,ou=people,dc=example,dc=com"
	alicePW   = "alicepw"
	opsDN     = "cn=ops,ou=groups,dc=example,dc=com"
	devDN     = "cn=dev,ou=groups,dc=example,dc=com"
	aliceUUID = "7C2F3A4E-1111-2222-3333-444455556666"
)

// fakeDirectory is a minimal LDAP server over TLS: simple bind for two
// accounts and searches for one user and her groups.
type fakeDirectory struct {
	addr    string
	caPEM   string
	conns   atomic.Int32
	binds   atomic.Int32
	closeFn func()
}

func startFakeDirectory(t *testing.T) *fakeDirectory {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake-ldap"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	fd := &fakeDirectory{addr: ln.Addr().String(), caPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), closeFn: func() { _ = ln.Close() }}
	t.Cleanup(fd.closeFn)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			fd.conns.Add(1)
			go fd.serve(c)
		}
	}()
	return fd
}

func (fd *fakeDirectory) serve(c net.Conn) {
	defer c.Close()
	for {
		pkt, err := ber.ReadPacket(c)
		if err != nil || len(pkt.Children) < 2 {
			return
		}
		msgID, _ := pkt.Children[0].Value.(int64)
		op := pkt.Children[1]
		switch op.Tag {
		case 0: // BindRequest
			fd.binds.Add(1)
			name, _ := op.Children[1].Value.(string)
			pw := op.Children[2].Data.String()
			code := goldap.LDAPResultInvalidCredentials
			if (name == svcDN && pw == svcPW) || (name == aliceDN && pw == alicePW) {
				code = goldap.LDAPResultSuccess
			}
			write(c, result(msgID, 1, code))
		case 2: // UnbindRequest
			return
		case 3: // SearchRequest
			base, _ := op.Children[0].Value.(string)
			filter, _ := goldap.DecompileFilter(op.Children[6])
			fd.search(c, msgID, strings.ToLower(base), filter)
		default:
			return
		}
	}
}

func (fd *fakeDirectory) search(c net.Conn, msgID int64, base, filter string) {
	switch {
	case strings.Contains(base, "ou=people") && strings.Contains(filter, "(uid=alice)"):
		write(c, entry(msgID, aliceDN, map[string][]string{
			"uid": {"alice"}, "displayName": {"Alice Example"}, "mail": {"Alice@Example.com"},
			"entryUUID": {aliceUUID}, "memberOf": {opsDN, devDN},
		}))
	case strings.Contains(base, "ou=groups") && strings.Contains(filter, strings.ToLower("(member="+aliceDN+")")):
		write(c, entry(msgID, opsDN, map[string][]string{"cn": {"ops"}}))
		write(c, entry(msgID, devDN, map[string][]string{"cn": {"dev"}}))
	}
	write(c, result(msgID, 5, goldap.LDAPResultSuccess))
}

func result(msgID int64, appTag ber.Tag, code int) *ber.Packet {
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))
	res := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appTag, nil, "Result")
	res.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), "resultCode"))
	res.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	res.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	msg.AppendChild(res)
	return msg
}

func entry(msgID int64, dn string, attrs map[string][]string) *ber.Packet {
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))
	e := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "SearchResultEntry")
	e.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "objectName"))
	list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for name, vals := range attrs {
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "type"))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		for _, v := range vals {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "val"))
		}
		a.AppendChild(set)
		list.AppendChild(a)
	}
	e.AppendChild(list)
	msg.AppendChild(e)
	return msg
}

func write(c net.Conn, p *ber.Packet) { _, _ = c.Write(p.Bytes()) }

func baseConfig(fd *fakeDirectory) *idp.LDAPConfig {
	return &idp.LDAPConfig{
		URL: "ldaps://" + fd.addr, CACertPEM: fd.caPEM,
		BindDN: svcDN, BindPassword: svcPW, BaseDN: "ou=people,dc=example,dc=com",
		UserFilter: "(&(objectClass=person)(uid=%s))", UsernameAttr: "uid", DisplayNameAttr: "displayName", EmailAttr: "mail",
		GroupAttr: "memberOf",
	}
}

func TestAuthenticate(t *testing.T) {
	fd := startFakeDirectory(t)
	a := &Authenticator{Timeout: 3 * time.Second}
	ctx := context.Background()

	id, err := a.Authenticate(ctx, baseConfig(fd), "alice", alicePW)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if id.Username != "alice" || id.DisplayName != "Alice Example" || id.Email != "alice@example.com" {
		t.Fatalf("identity: %+v", id)
	}
	if id.ExternalID != "uuid:"+strings.ToLower(aliceUUID) {
		t.Fatalf("external id: %q", id.ExternalID)
	}
	if strings.Join(id.Groups, ",") != "ops,dev" {
		t.Fatalf("groups from memberOf: %v", id.Groups)
	}

	// Group search mode instead of memberOf.
	cfg := baseConfig(fd)
	cfg.GroupAttr, cfg.GroupBaseDN, cfg.GroupFilter, cfg.GroupNameAttr = "", "ou=groups,dc=example,dc=com", "(member=%s)", "cn"
	id, err = a.Authenticate(ctx, cfg, "alice", alicePW)
	if err != nil || strings.Join(id.Groups, ",") != "ops,dev" {
		t.Fatalf("group search: %v %v", id, err)
	}

	// Username suffix: "alice" is tried, then "alice@example.com"; the fake
	// only knows uid=alice so the first candidate wins.
	cfg = baseConfig(fd)
	cfg.UsernameSuffix = "@example.com"
	if _, err := a.Authenticate(ctx, cfg, "alice", alicePW); err != nil {
		t.Fatalf("suffix: %v", err)
	}

	wrong := []struct {
		user, pw string
	}{{"alice", "nope"}, {"mallory", alicePW}, {"alice)(uid=*", alicePW}}
	for _, w := range wrong {
		if _, err := a.Authenticate(ctx, baseConfig(fd), w.user, w.pw); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("%q/%q: expected ErrInvalidCredentials, got %v", w.user, w.pw, err)
		}
	}
}

func TestEmptyPasswordNeverReachesDirectory(t *testing.T) {
	fd := startFakeDirectory(t)
	a := &Authenticator{}
	before := fd.conns.Load()
	for _, pw := range []string{"", "   "} {
		if _, err := a.Authenticate(context.Background(), baseConfig(fd), "alice", pw); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("empty password: %v", err)
		}
	}
	if fd.conns.Load() != before {
		t.Fatal("empty password must be refused before connecting")
	}
}

func TestTLSPinningAndTest(t *testing.T) {
	fd := startFakeDirectory(t)
	a := &Authenticator{Timeout: 3 * time.Second}
	ctx := context.Background()

	if err := a.Test(ctx, baseConfig(fd)); err != nil {
		t.Fatalf("Test: %v", err)
	}
	other := startFakeDirectory(t) // a different CA
	cfg := baseConfig(fd)
	cfg.CACertPEM = other.caPEM
	if _, err := a.Authenticate(ctx, cfg, "alice", alicePW); !errors.Is(err, ErrDirectory) {
		t.Fatalf("wrong CA: expected ErrDirectory, got %v", err)
	}
	cfg = baseConfig(fd)
	cfg.CACertPEM = ""
	if _, err := a.Authenticate(ctx, cfg, "alice", alicePW); !errors.Is(err, ErrConfig) {
		t.Fatalf("missing CA: expected ErrConfig, got %v", err)
	}
	cfg = baseConfig(fd)
	cfg.BindPassword = "bad"
	if err := a.Test(ctx, cfg); !errors.Is(err, ErrDirectory) {
		t.Fatalf("bad service password: expected ErrDirectory, got %v", err)
	}
	cfg = baseConfig(fd)
	cfg.URL = "ldap://" + fd.addr
	if _, err := a.Authenticate(ctx, cfg, "alice", alicePW); !errors.Is(err, ErrConfig) {
		t.Fatalf("plain ldap without starttls: expected ErrConfig, got %v", err)
	}
}

func TestObjectGUIDFormat(t *testing.T) {
	// Bytes as stored by AD for {2f1a6c3e-9b7d-4e21-8f3a-0123456789ab}.
	raw := []byte{0x3e, 0x6c, 0x1a, 0x2f, 0x7d, 0x9b, 0x21, 0x4e, 0x8f, 0x3a, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab}
	if got := formatObjectGUID(raw); got != "2f1a6c3e-9b7d-4e21-8f3a-0123456789ab" {
		t.Fatalf("guid: %s", got)
	}
	if firstRDNValue("cn=ops,ou=groups,dc=example,dc=com") != "ops" || firstRDNValue("garbage") != "" {
		t.Fatal("first rdn")
	}
}
