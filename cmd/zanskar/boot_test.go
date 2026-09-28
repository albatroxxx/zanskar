// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/config"
)

// TestDescribeDSNNeverShowsAPassword: whatever shape the DSN takes, the boot
// table names only the host and database, never the credential.
func TestDescribeDSNNeverShowsAPassword(t *testing.T) {
	const secret = "hunter2-Secret"
	cases := []struct{ driver, dsn, want string }{
		{config.DriverPostgres, "postgres://zanskar:" + secret + "@db.internal:5432/zanskar?sslmode=require", "postgres zanskar on db.internal:5432"},
		{config.DriverPostgres, "postgres://db.internal/zanskar?user=zanskar&password=" + secret, "postgres zanskar on db.internal"},
		{config.DriverPostgres, "host=db.internal port=5432 user=zanskar password=" + secret + " dbname=zanskar sslmode=require", "postgres zanskar on db.internal:5432"},
		{config.DriverPostgres, "password=" + secret, "postgres (configured)"},
		{config.DriverPostgres, "postgres://" + secret + "@[::1]/", "postgres on ::1"},
		{config.DriverSQLite, "file:/var/lib/zanskar/zanskar.db?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", "sqlite /var/lib/zanskar/zanskar.db"},
		{config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)", "sqlite (in memory)"},
	}
	for _, c := range cases {
		got := describeDSN(c.driver, c.dsn)
		if got != c.want {
			t.Errorf("describeDSN(%s, %q) = %q, want %q", c.driver, c.dsn, got, c.want)
		}
		if strings.Contains(got, secret) {
			t.Errorf("describeDSN(%q) leaked the password: %q", c.dsn, got)
		}
	}
}

// TestBootSettingsMaskSecrets: the boot list a panel renders carries no
// master key and no database password, and names the variable to edit.
func TestBootSettingsMaskSecrets(t *testing.T) {
	cfg := &config.Config{ListenAddr: "127.0.0.1:8443", DBDriver: config.DriverPostgres,
		DBDSN: "postgres://zanskar:pa55word@db/zanskar", MasterKey: []byte("0123456789abcdef0123456789abcdef"),
		LogFormat: "json", RecordingsDir: "/var/lib/zanskar/recordings", Issuer: "Zanskar"}
	for _, b := range bootSettings(cfg, 3) {
		if b.EnvVar == "" || b.Title == "" {
			t.Errorf("boot setting %s lacks a title or variable", b.Key)
		}
		if strings.Contains(b.Value, "pa55word") || strings.Contains(b.Value, "0123456789abcdef") {
			t.Errorf("boot setting %s shows a secret: %q", b.Key, b.Value)
		}
		if b.Key == "master_key" && b.Value != "set (data-key version 3 active)" {
			t.Errorf("master key shown as %q", b.Value)
		}
	}
}
