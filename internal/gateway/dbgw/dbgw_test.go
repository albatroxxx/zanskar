// SPDX-License-Identifier: Apache-2.0

package dbgw

import (
	"slices"
	"strings"
	"testing"

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
	s := Spec{Engine: "postgres", Host: "db.internal", Port: 5432, Database: "app", Username: "svc", Password: "s3cret", SessionID: "sess1"}
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
		s := Spec{Engine: engine, Host: "db.internal", Port: 3306, Database: "app", Username: "svc", Password: "s3cret", SessionID: "sess1", ProxyImage: "ghcr.io/albatroxxx/zanskar:1.2.3"}
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
