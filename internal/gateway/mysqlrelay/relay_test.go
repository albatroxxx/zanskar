// SPDX-License-Identifier: Apache-2.0

package mysqlrelay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
)

// fakeDB is an upstream MySQL: a go-mysql server with one real credential
// and a handler that answers a few queries, including one whose result is
// larger than a single protocol packet.
type fakeDB struct {
	server.EmptyHandler
	big string
}

func (f fakeDB) HandleQuery(q string) (*mysql.Result, error) {
	switch strings.ToUpper(strings.TrimSpace(q)) {
	case "SELECT 1":
		rs, err := mysql.BuildSimpleTextResultset([]string{"1"}, [][]any{{int64(1)}})
		if err != nil {
			return nil, err
		}
		return mysql.NewResult(rs), nil
	case "SELECT BIG":
		rs, err := mysql.BuildSimpleTextResultset([]string{"big"}, [][]any{{f.big}})
		if err != nil {
			return nil, err
		}
		return mysql.NewResult(rs), nil
	}
	return nil, mysql.NewError(mysql.ER_UNKNOWN_ERROR, "fake: "+q)
}

// startFake serves a fake upstream on a loopback port. withTLS uses
// go-mysql's default server, which generates a certificate and defaults to
// caching_sha2_password, so the relay's TLS path and full authentication
// are exercised; otherwise plain mysql_native_password.
func startFake(t *testing.T, user, password string, withTLS bool, big string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var srv *server.Server
	var auth *server.InMemoryAuthenticationHandler
	if withTLS {
		srv = server.NewDefaultServer()
		auth = server.NewInMemoryAuthenticationHandler(mysql.AUTH_CACHING_SHA2_PASSWORD)
	} else {
		srv = server.NewServer("8.0.99-fake", mysql.DEFAULT_COLLATION_ID, mysql.AUTH_NATIVE_PASSWORD, nil, nil)
		auth = server.NewInMemoryAuthenticationHandler(mysql.AUTH_NATIVE_PASSWORD)
	}
	if err := auth.AddUser(user, password); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				conn, err := srv.NewCustomizedConn(c, auth, fakeDB{big: big})
				if err != nil {
					return
				}
				for {
					if err := conn.HandleCommand(); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func startRelay(t *testing.T, cfg Config) string {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Relay{Config: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return ln.Addr().String()
}

// cli connects like a conforming MySQL client: it takes the server's offer
// and asks for nothing the server did not advertise.
func cli(addr, user string) (*client.Conn, error) {
	return client.Connect(addr, user, "", "", func(c *client.Conn) error {
		c.UnsetCapability(mysql.CLIENT_DEPRECATE_EOF)
		c.UnsetCapability(mysql.CLIENT_QUERY_ATTRIBUTES)
		for _, f := range []uint32{mysql.CLIENT_SESSION_TRACK, mysql.CLIENT_MULTI_RESULTS, mysql.CLIENT_PS_MULTI_RESULTS} {
			if err := c.SetCapability(f); err != nil {
				return err
			}
		}
		return nil
	})
}

// TestRelayEndToEnd: the client signs in with no password as the session
// user and gets real results through the relay, including a result set
// larger than one packet, over plain and over TLS upstream links.
func TestRelayEndToEnd(t *testing.T) {
	big := strings.Repeat("z", 17<<20)
	for _, withTLS := range []bool{false, true} {
		name := "plain"
		if withTLS {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			upstream := startFake(t, "svc", "s3cret", withTLS, big)
			relay := startRelay(t, Config{Upstream: Upstream{Addr: upstream, User: "svc", Password: "s3cret", Database: "app"}})
			c, err := cli(relay, "svc")
			if err != nil {
				t.Fatalf("connect through relay: %v", err)
			}
			defer func() { _ = c.Close() }()
			if !strings.Contains(c.GetServerVersion(), "fake") && !withTLS {
				t.Fatalf("client sees the upstream version, got %q", c.GetServerVersion())
			}
			res, err := c.Execute("SELECT 1")
			if err != nil {
				t.Fatalf("select 1: %v", err)
			}
			if v, _ := res.GetString(0, 0); v != "1" {
				t.Fatalf("select 1 returned %q", v)
			}
			res, err = c.Execute("SELECT BIG")
			if err != nil {
				t.Fatalf("select big: %v", err)
			}
			if v, _ := res.GetString(0, 0); len(v) != len(big) {
				t.Fatalf("big result: %d bytes, want %d", len(v), len(big))
			}
			if err := c.Ping(); err != nil {
				t.Fatalf("ping: %v", err)
			}
			// A second connection while the first is open: the CLI's \r.
			c2, err := cli(relay, "svc")
			if err != nil {
				t.Fatalf("second connect: %v", err)
			}
			_ = c2.Close()
		})
	}
}

// TestRelayRefusals: another username, a wrong upstream credential, an
// unreachable upstream, and a client that insists on framing flags the
// server did not offer are each refused in the client's own sign-in with
// a proper error packet, and nothing about the upstream leaks.
func TestRelayRefusals(t *testing.T) {
	upstream := startFake(t, "svc", "s3cret", false, "")
	relay := startRelay(t, Config{Upstream: Upstream{Addr: upstream, User: "svc", Password: "s3cret"}})
	if _, err := cli(relay, "root"); err == nil || !strings.Contains(err.Error(), "signs in as 'svc'") {
		t.Fatalf("other user: %v", err)
	}
	// A client that echoes flags the relay never offered (go-mysql's client
	// sends DEPRECATE_EOF and QUERY_ATTRIBUTES unasked, as libmysqlclient
	// does) is fine: it can only use what was offered. One that lacks a
	// framing flag the upstream has, here multi-results, is refused.
	var my *mysql.MyError
	if _, err := client.Connect(relay, "svc", "", ""); err == nil || !errors.As(err, &my) || my.Code != mysql.ER_NOT_SUPPORTED_YET {
		t.Fatalf("client without multi-results must be refused as not supported: %v", err)
	}
	c, err := client.Connect(relay, "svc", "", "", func(c *client.Conn) error {
		for _, f := range []uint32{mysql.CLIENT_SESSION_TRACK, mysql.CLIENT_MULTI_RESULTS, mysql.CLIENT_PS_MULTI_RESULTS} {
			if err := c.SetCapability(f); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("client echoing unoffered flags must still connect: %v", err)
	}
	if _, err := c.Execute("SELECT 1"); err != nil {
		t.Fatalf("select through such a client: %v", err)
	}
	_ = c.Close()

	bad := startRelay(t, Config{Upstream: Upstream{Addr: upstream, User: "svc", Password: "wrong"}})
	if _, err := cli(bad, "svc"); err == nil || !errors.As(err, &my) || my.Code != mysql.ER_ACCESS_DENIED_ERROR {
		t.Fatalf("wrong upstream password must surface the server's refusal: %v", err)
	}

	down := startRelay(t, Config{Upstream: Upstream{Addr: "127.0.0.1:1", User: "svc", Password: "s3cret"}, DialTimeout: 2 * time.Second})
	_, err = cli(down, "svc")
	if err == nil || !strings.Contains(err.Error(), "did not accept the connection") || strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("unreachable upstream must be a clean error without the address: %v", err)
	}
}

// TestRelayBlocksChangeUser: COM_CHANGE_USER is answered by the relay,
// never forwarded, and the session goes on afterwards.
func TestRelayBlocksChangeUser(t *testing.T) {
	upstream := startFake(t, "svc", "s3cret", false, "")
	relay := startRelay(t, Config{Upstream: Upstream{Addr: upstream, User: "svc", Password: "s3cret"}})
	c, err := cli(relay, "svc")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	c.ResetSequence()
	pkt := append([]byte{0, 0, 0, 0, mysql.COM_CHANGE_USER}, "root\x00\x00mysql_native_password\x00"...)
	if err := c.WritePacket(pkt); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if resp[0] != mysql.ERR_HEADER || !bytes.Contains(resp, []byte("re-authentication")) {
		t.Fatalf("change user answered with %q", resp)
	}
	if _, err := c.Execute("SELECT 1"); err != nil {
		t.Fatalf("session must continue after the refusal: %v", err)
	}
}

// TestPacedRead: two packets written at once come back one per Read, so a
// buffered reader on top can never hold part of the next packet.
func TestPacedRead(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	p1 := []byte{3, 0, 0, 0, 'a', 'b', 'c'}
	p2 := []byte{2, 0, 0, 1, 'd', 'e'}
	go func() {
		_, _ = b.Write(append(append([]byte{}, p1...), p2...))
		_ = b.Close()
	}()
	r := newPaced(a)
	buf := make([]byte, 64)
	n, err := r.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], p1) {
		t.Fatalf("first read %q %v", buf[:n], err)
	}
	// Small reads inside one packet never cross into the next either.
	n, _ = r.Read(buf[:1])
	if n != 1 || buf[0] != 2 {
		t.Fatalf("partial header read %d %v", n, buf[:n])
	}
	n, _ = io.ReadFull(r, buf[:5])
	if n != 5 || !bytes.Equal(buf[:5], p2[1:]) {
		t.Fatalf("rest of second packet %q", buf[:n])
	}
}

// TestFramingMismatch: the predicate ignores bits the relay never offered
// and flags a framing capability that only one side holds.
func TestFramingMismatch(t *testing.T) {
	up := requested
	if d := framingMismatch(requested|mysql.CLIENT_DEPRECATE_EOF|mysql.CLIENT_QUERY_ATTRIBUTES, up); d != 0 {
		t.Fatalf("unoffered bits must not count: %s", capNames(d))
	}
	if d := framingMismatch(requested, up&^mysql.CLIENT_SESSION_TRACK); d != mysql.CLIENT_SESSION_TRACK {
		t.Fatalf("upstream without session track: %s", capNames(d))
	}
	if d := framingMismatch(requested&^mysql.CLIENT_MULTI_RESULTS, up); d != mysql.CLIENT_MULTI_RESULTS {
		t.Fatalf("client without multi results: %s", capNames(d))
	}
}

// TestParse: the sidecar's JSON config gets defaults and validation.
func TestParse(t *testing.T) {
	c, err := Parse([]byte(`{"upstream":{"addr":"db.internal:3306","user":"svc","password":"x"}}`))
	if err != nil || c.Listen != ":3306" || c.User != "svc" || c.Upstream.TLS != TLSPrefer {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	for _, bad := range []string{`{}`, `{"upstream":{"addr":"db","user":"svc"}}`, `{"upstream":{"addr":"db:1","user":"svc","tls":"maybe"}}`} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatalf("%s must be refused", bad)
		}
	}
}

// testCA makes a CA and a server certificate for 127.0.0.1 signed by it.
func testCA(t *testing.T) (caPEM string, serverCert tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "db"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}
}

// TestRelayVerifyFull: with the server's CA the chain and host name verify
// and the session works; with another CA the upstream is refused and the
// client gets a clean error, never a plaintext fallback.
func TestRelayVerifyFull(t *testing.T) {
	caPEM, cert := testCA(t)
	otherCA, _ := testCA(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := server.NewServer("8.0.99-tls", mysql.DEFAULT_COLLATION_ID, mysql.AUTH_NATIVE_PASSWORD, nil, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	auth := server.NewInMemoryAuthenticationHandler(mysql.AUTH_NATIVE_PASSWORD)
	_ = auth.AddUser("svc", "s3cret")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				conn, err := srv.NewCustomizedConn(c, auth, fakeDB{})
				if err != nil {
					return
				}
				for conn.HandleCommand() == nil {
				}
			}()
		}
	}()
	good := startRelay(t, Config{Upstream: Upstream{Addr: ln.Addr().String(), User: "svc", Password: "s3cret", TLS: TLSVerifyFull, CA: caPEM}})
	c, err := cli(good, "svc")
	if err != nil {
		t.Fatalf("verify-full with the right CA: %v", err)
	}
	if _, err := c.Execute("SELECT 1"); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	bad := startRelay(t, Config{Upstream: Upstream{Addr: ln.Addr().String(), User: "svc", Password: "s3cret", TLS: TLSVerifyFull, CA: otherCA}, DialTimeout: 3 * time.Second})
	if _, err := cli(bad, "svc"); err == nil || !strings.Contains(err.Error(), "did not accept") {
		t.Fatalf("verify-full with the wrong CA must fail closed: %v", err)
	}
	if _, err := Parse([]byte(`{"upstream":{"addr":"db:3306","user":"svc","tls":"verify-full","ca":"not a cert"}}`)); err == nil {
		t.Fatal("a CA that is not PEM must be refused")
	}
}
