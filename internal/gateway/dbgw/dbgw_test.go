// SPDX-License-Identifier: Apache-2.0

package dbgw

import (
	"slices"
	"strings"
	"testing"
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

func TestRunArgsSecurity(t *testing.T) {
	s := Spec{Engine: "postgres", Version: "16", Host: "db.internal", Port: 5432, Database: "app", Username: "svc", Password: "s3cret", SessionID: "sess1", Network: "zanskar"}
	args, env, err := runArgs(s)
	if err != nil {
		t.Fatal(err)
	}
	// The password must never appear in the argument vector (host `ps`).
	for _, a := range args {
		if strings.Contains(a, "s3cret") {
			t.Fatalf("password leaked into argv: %q", a)
		}
	}
	// It rides the process environment instead, referenced by name in argv.
	if !slices.Contains(env, "PGPASSWORD=s3cret") {
		t.Fatalf("password not carried in env: %v", env)
	}
	if !slices.Contains(args, "PGPASSWORD") {
		t.Fatal("expected -e PGPASSWORD (name only) in args")
	}
	// Hardening flags.
	for _, want := range []string{"--rm", "no-new-privileges", "ALL", "--read-only"} {
		if !slices.Contains(args, want) {
			t.Errorf("missing hardening flag %q", want)
		}
	}
	// Image and connection arguments.
	if !slices.Contains(args, "postgres:16-alpine") {
		t.Error("client image missing")
	}
	if j := strings.Join(args, " "); !strings.Contains(j, "psql -h db.internal -p 5432 -U svc") {
		t.Errorf("psql connection args wrong: %s", j)
	}
	if !slices.Contains(args, "-d") || !slices.Contains(args, "app") {
		t.Error("database name missing")
	}
	if !slices.Contains(args, "zanskar") {
		t.Error("network missing")
	}
}

func TestRunArgsMySQLAndErrors(t *testing.T) {
	a, env, err := runArgs(Spec{Engine: "mysql", Host: "h", Port: 3306, Username: "u", Password: "p", SessionID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(env, "MYSQL_PWD=p") || !slices.Contains(a, "MYSQL_PWD") {
		t.Fatalf("mysql password env: %v / %v", a, env)
	}
	if j := strings.Join(a, " "); !strings.Contains(j, "mysql --protocol=TCP -h h -P 3306 -u u") {
		t.Errorf("mysql connection args wrong: %s", j)
	}
	if _, _, err := runArgs(Spec{Engine: "oracle", Host: "h", Port: 1, Username: "u"}); err == nil {
		t.Fatal("expected an unsupported-engine error")
	}
	if _, _, err := runArgs(Spec{Engine: "postgres", Port: 5432, Username: "u"}); err == nil {
		t.Fatal("expected a missing-host error")
	}
}
