// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestDatabaseTargetValidate(t *testing.T) {
	// A valid engine defaults os_family to "other" and the port to the engine's.
	pg := &Target{Name: "pg", Address: "db.example.com", Engine: "postgres"}
	if err := pg.Validate(); err != nil {
		t.Fatalf("valid postgres target: %v", err)
	}
	if pg.OSFamily != OtherOS {
		t.Fatalf("os_family should default to other, got %q", pg.OSFamily)
	}
	if !pg.IsDatabase() {
		t.Fatal("IsDatabase should be true")
	}
	if pg.Port(Database) != 5432 {
		t.Fatalf("postgres default port = %d, want 5432", pg.Port(Database))
	}

	// Engine is trimmed and lower-cased.
	my := &Target{Name: "my", Address: "db2", Engine: "  MySQL "}
	if err := my.Validate(); err != nil {
		t.Fatalf("mysql: %v", err)
	}
	if my.Engine != "mysql" || my.Port(Database) != 3306 {
		t.Fatalf("engine=%q port=%d", my.Engine, my.Port(Database))
	}

	// An unknown engine is rejected.
	bad := &Target{Name: "bad", Address: "db3", Engine: "oracle"}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected an unknown engine to be rejected")
	}

	// An explicit port override wins over the engine default.
	over := &Target{Name: "over", Address: "db4", Engine: "postgres", Ports: map[Protocol]int{Database: 6432}}
	if err := over.Validate(); err != nil {
		t.Fatal(err)
	}
	if over.Port(Database) != 6432 {
		t.Fatalf("override port = %d, want 6432", over.Port(Database))
	}

	// A non-database target is unaffected.
	host := &Target{Name: "host", Address: "10.0.0.1", OSFamily: Linux}
	if err := host.Validate(); err != nil {
		t.Fatal(err)
	}
	if host.IsDatabase() {
		t.Fatal("a host target must not be a database")
	}
}

func TestDatabaseTargetRoundTrip(t *testing.T) {
	r := NewRepo(testDB(t))
	dbt := &Target{Name: "pgtest", Address: "pg.internal", Engine: "postgres", EngineVersion: "16"}
	if err := r.Create(context.Background(), dbt); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := r.GetByName(context.Background(), "pgtest")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Engine != "postgres" || got.EngineVersion != "16" {
		t.Fatalf("engine=%q version=%q, want postgres/16", got.Engine, got.EngineVersion)
	}
	if !got.IsDatabase() || got.Port(Database) != 5432 {
		t.Fatalf("round-tripped target is not a postgres database: %+v", got)
	}
}

func TestServableEngine(t *testing.T) {
	cases := []struct {
		engine string
		want   bool
	}{
		{"postgres", true},
		{" Postgres ", true}, // trimmed and lower-cased like Validate does
		{"mysql", true},
		{"mariadb", true},
		{"MariaDB", true},
		{"", false},
		{"oracle", false},
	}
	for _, c := range cases {
		if got := ServableEngine(c.engine); got != c.want {
			t.Errorf("ServableEngine(%q) = %v, want %v", c.engine, got, c.want)
		}
	}
}

// TestTargetRetentionDays: the override round-trips and is validated.
func TestTargetRetentionDays(t *testing.T) {
	ctx := context.Background()
	repo := NewRepo(testDB(t))
	days := 30
	tgt := &Target{Name: "keep-a-month", Address: "10.0.0.9", OSFamily: Linux, RetentionDays: &days}
	if err := repo.Create(ctx, tgt); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Get(ctx, tgt.ID)
	if err != nil || got.RetentionDays == nil || *got.RetentionDays != 30 {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	too := 4000
	if err := (&Target{Name: "x", Address: "10.0.0.10", OSFamily: Linux, RetentionDays: &too}).Validate(); err == nil {
		t.Fatal("4000 days must be refused")
	}
}

// TestDatabaseTargetSettings: database name, TLS mode and CA are validated
// and stored; a host keeps none of them.
func TestDatabaseTargetSettings(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	repo := NewRepo(db)
	tgt := &Target{Name: "orders", Address: "db.internal", Engine: "MySQL", DatabaseName: " orders ", TLSMode: "Verify-Full", TLSCA: testCAPEM}
	if err := repo.Create(ctx, tgt); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Get(ctx, tgt.ID)
	if err != nil || got.DatabaseName != "orders" || got.TLSMode != TLSVerifyFull || got.TLSCA != strings.TrimSpace(testCAPEM) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if err := (&Target{Name: "d", Address: "db", Engine: "postgres"}).Validate(); err != nil {
		t.Fatal(err)
	}
	if d := (&Target{Name: "d", Address: "db", Engine: "postgres"}); d.Validate() == nil && d.TLSMode != TLSPrefer {
		t.Fatalf("default tls mode: %q", d.TLSMode)
	}
	for _, bad := range []Target{
		{Name: "d", Address: "db", Engine: "postgres", TLSMode: "maybe"},
		{Name: "d", Address: "db", Engine: "postgres", DatabaseName: "app; drop"},
		{Name: "d", Address: "db", Engine: "postgres", TLSCA: "not pem"},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v must be refused", bad)
		}
	}
	host := &Target{Name: "h", Address: "10.0.0.5", OSFamily: Linux, DatabaseName: "x", TLSMode: "require", TLSCA: testCAPEM}
	if err := host.Validate(); err != nil || host.DatabaseName != "" || host.TLSMode != "" || host.TLSCA != "" {
		t.Fatalf("a host keeps no database settings: %+v %v", host, err)
	}
}

// testCAPEM is a self-signed certificate generated for the test run.
var testCAPEM = func() string {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}()
