// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"testing"
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
		{"mysql", false},
		{"mariadb", false},
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
