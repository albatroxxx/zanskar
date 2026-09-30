// SPDX-License-Identifier: Apache-2.0

package dbgw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/gateway/mysqlrelay"
)

func TestClientImage(t *testing.T) {
	cases := []struct{ engine, version, want string }{
		{"postgres", "", "postgres:16-alpine"},
		{"postgres", "15", "postgres:15-alpine"},
		{"mysql", "", "mysql:8"},
		{"mariadb", "11", "mariadb:11"},
		{"oracle", "", ""},
	}
	for _, c := range cases {
		if got := ClientImage(c.engine, c.version); got != c.want {
			t.Errorf("ClientImage(%q,%q)=%q want %q", c.engine, c.version, got, c.want)
		}
	}
}

func TestProxyArgsHoldsCredential(t *testing.T) {
	s := Spec{Engine: "postgres", Host: "db.internal", Port: 5432, Database: "app", Username: "svc", Password: "s3cret", SessionID: "sess1", TLSMode: "prefer"}
	args, env, err := proxyArgs(s, "zanskar-net-sess1", "zanskar-dbproxy-sess1")
	if err != nil {
		t.Fatal(err)
	}
	// The credential must never be in the argv (host `ps`).
	for _, a := range args {
		if strings.Contains(a, "s3cret") {
			t.Fatalf("credential leaked into proxy argv: %q", a)
		}
	}
	// It rides the sidecar's environment via PGB_INI (passed by name in argv),
	// and the config is materialised in-container by the entrypoint override.
	if !slices.Contains(args, "PGB_INI") || !slices.Contains(args, "--entrypoint") {
		t.Fatalf("expected -e PGB_INI and an entrypoint override, got %v", args)
	}
	found := false
	for _, e := range env {
		if strings.HasPrefix(e, "PGB_INI=") && strings.Contains(e, "s3cret") &&
			strings.Contains(e, "db.internal") && strings.Contains(e, "auth_type=trust") &&
			strings.Contains(e, "server_tls_sslmode=prefer") {
			found = true
		}
	}
	if !found {
		t.Fatalf("upstream credential/config not carried in the sidecar env: %v", env)
	}
	for _, want := range []string{"no-new-privileges", "ALL", "edoburu/pgbouncer:v1.23.1-p3"} {
		if !slices.Contains(args, want) {
			t.Errorf("proxy missing %q", want)
		}
	}
	// mysql without a proxy image configured cannot start a sidecar.
	if _, _, err := proxyArgs(Spec{Engine: "mysql", Host: "h", Port: 3306, Username: "u"}, "n", "p"); err == nil {
		t.Fatal("expected no-proxy error for mysql without an image")
	}
}

// TestMySQLProxyArgsHoldsCredential: the MySQL sidecar is the gateway's own
// image running dbproxy; its configuration rides one environment variable
// passed by name, so neither the credential nor the upstream host is in argv.
func TestMySQLProxyArgsHoldsCredential(t *testing.T) {
	for _, engine := range []string{"mysql", "mariadb"} {
		s := Spec{Engine: engine, Host: "db.internal", Port: 3306, Database: "app", Username: "svc", Password: "s3cret", SessionID: "sess1", ProxyImage: "ghcr.io/albatroxxx/zanskar:1.2.3", TLSMode: "require"}
		args, env, err := proxyArgs(s, "zanskar-net-sess1", "zanskar-dbproxy-sess1")
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range args {
			if strings.Contains(a, "s3cret") || strings.Contains(a, "db.internal") {
				t.Fatalf("%s: secret or host in proxy argv: %q", engine, a)
			}
		}
		for _, want := range []string{"ZANSKAR_DBPROXY", "ghcr.io/albatroxxx/zanskar:1.2.3", "dbproxy", "no-new-privileges", "--read-only"} {
			if !slices.Contains(args, want) {
				t.Errorf("%s: proxy argv missing %q: %v", engine, want, args)
			}
		}
		if len(env) != 1 || !strings.HasPrefix(env[0], "ZANSKAR_DBPROXY={") {
			t.Fatalf("%s: env %v", engine, env)
		}
		cfg, err := mysqlrelay.Parse([]byte(strings.TrimPrefix(env[0], "ZANSKAR_DBPROXY=")))
		if err != nil || cfg.Upstream.Addr != "db.internal:3306" || cfg.Upstream.Password != "s3cret" || cfg.User != "svc" || cfg.Upstream.Database != "app" || cfg.Listen != ":3306" {
			t.Fatalf("%s: sidecar config %+v %v", engine, cfg, err)
		}
	}
}

// TestMySQLClientArgs: the client container gets the CLI for its engine,
// pointed at the sidecar with no password flag and no upstream host.
func TestMySQLClientArgs(t *testing.T) {
	for engine, want := range map[string]string{"mysql": "mysql:8 mysql --protocol=TCP -h zanskar-dbproxy-sess1 -P 3306 -u svc app", "mariadb": "mariadb:11 mariadb --protocol=TCP -h zanskar-dbproxy-sess1 -P 3306 -u svc app"} {
		s := Spec{Engine: engine, Host: "db.internal", Port: 3306, Database: "app", Username: "svc", Password: "s3cret", SessionID: "sess1"}
		args, err := clientArgs(s, "zanskar-net-sess1", "zanskar-dbcli-sess1", "zanskar-dbproxy-sess1")
		if err != nil {
			t.Fatal(err)
		}
		j := strings.Join(args, " ")
		if !strings.HasSuffix(j, want) || strings.Contains(j, "s3cret") || strings.Contains(j, "db.internal") {
			t.Errorf("%s: client argv %s", engine, j)
		}
		for _, a := range args {
			if a == "-p" || strings.HasPrefix(a, "--password") {
				t.Errorf("%s: the client must not be given a password flag: %s", engine, j)
			}
		}
	}
}

func TestClientArgsHasNoCredential(t *testing.T) {
	s := Spec{Engine: "postgres", Version: "16", Host: "db.internal", Port: 5432, Database: "app", Username: "svc", Password: "s3cret", SessionID: "sess1"}
	args, err := clientArgs(s, "zanskar-net-sess1", "zanskar-dbcli-sess1", "zanskar-dbproxy-sess1")
	if err != nil {
		t.Fatal(err)
	}
	// The client container must carry NO credential anywhere — not the password,
	// not the upstream host. It only talks to the proxy.
	for _, a := range args {
		if strings.Contains(a, "s3cret") || strings.Contains(a, "db.internal") {
			t.Fatalf("client must not see the credential or upstream host: %q", a)
		}
	}
	j := strings.Join(args, " ")
	if !strings.Contains(j, "psql -h zanskar-dbproxy-sess1 -p 6432 -U svc") {
		t.Errorf("client should target the proxy: %s", j)
	}
	if !slices.Contains(args, "-d") || !slices.Contains(args, "app") {
		t.Error("database name missing from client args")
	}
	for _, want := range []string{"--read-only", "no-new-privileges", "postgres:16-alpine"} {
		if !slices.Contains(args, want) {
			t.Errorf("client missing hardening/image %q", want)
		}
	}
}

// TestSidecarTLSModes: the target's TLS mode reaches pgbouncer as its
// sslmode (with the CA file only for verify-full) and the MySQL relay as
// its tls setting with the CA bundle; no mode at all means verify-full.
func TestSidecarTLSModes(t *testing.T) {
	ca := testCertPEM()
	for mode, want := range map[string]string{"": "verify-full", "prefer": "prefer", "require": "require", "verify-full": "verify-full", "disable": "disable"} {
		s := Spec{Engine: "postgres", Host: "db", Port: 5432, Database: "app", Username: "svc", Password: "x", TLSMode: mode, TLSCA: ca}
		_, env, err := proxyArgs(s, "n", "p")
		if err != nil {
			t.Fatal(err)
		}
		ini := env[0]
		if !strings.Contains(ini, "server_tls_sslmode="+want+"\n") {
			t.Errorf("mode %q: %s", mode, ini)
		}
		if strings.Contains(ini, "server_tls_ca_file") != (want == "verify-full") {
			t.Errorf("mode %q: ca file line presence wrong: %s", mode, ini)
		}
		if !slices.Contains(env, "PGB_CA="+ca) {
			t.Errorf("mode %q: CA not passed in env", mode)
		}
		m := Spec{Engine: "mysql", Host: "db", Port: 3306, Username: "svc", Password: "x", TLSMode: mode, TLSCA: ca, ProxyImage: "img"}
		_, env, err = proxyArgs(m, "n", "p")
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := mysqlrelay.Parse([]byte(strings.TrimPrefix(env[0], "ZANSKAR_DBPROXY=")))
		if err != nil || string(cfg.Upstream.TLS) != want || cfg.Upstream.CA != ca {
			t.Errorf("mode %q: relay config %+v %v", mode, cfg.Upstream, err)
		}
	}
}

// testCertPEM is a self-signed certificate, since the relay refuses a CA
// bundle that does not parse.
func testCertPEM() string {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestSSLModeFailsClosed: a spec with no TLS mode (or one this build does not
// know) is verified, and pgbouncer is pointed at the CA file (ADR 0025).
func TestSSLModeFailsClosed(t *testing.T) {
	for _, m := range []string{"", "bogus"} {
		if got := sslMode(m); got != "verify-full" {
			t.Errorf("sslMode(%q)=%q want verify-full", m, got)
		}
	}
	for _, m := range []string{"disable", "prefer", "require", "verify-full"} {
		if got := sslMode(m); got != m {
			t.Errorf("sslMode(%q)=%q want it unchanged", m, got)
		}
	}
	s := Spec{Engine: "postgres", Host: "db", Port: 5432, Database: "app", Username: "u", Password: "p", SessionID: "s", TLSCA: "ca"}
	_, env, err := proxyArgs(s, "n", "p")
	if err != nil {
		t.Fatal(err)
	}
	ini := ""
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "PGB_INI="); ok {
			ini = v
		}
	}
	if !strings.Contains(ini, "server_tls_sslmode=verify-full") || !strings.Contains(ini, "server_tls_ca_file=/etc/pgbouncer/ca.pem") {
		t.Fatalf("an unset mode must verify against the CA file:\n%s", ini)
	}
}
