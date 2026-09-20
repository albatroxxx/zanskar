// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"os"
	"testing"

	"github.com/albatroxxx/zanskar/internal/config"
)

func openTestDB(t *testing.T, driver, dsn string) *DB {
	t.Helper()
	db, err := Open(context.Background(), driver, dsn)
	if err != nil {
		t.Fatalf("open %s: %v", driver, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func runMigrationSuite(t *testing.T, db *DB) {
	t.Helper()
	ctx := context.Background()

	pending, err := Pending(ctx, db)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) == 0 {
		t.Fatal("expected pending migrations on a fresh database")
	}

	ran, err := Migrate(ctx, db)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if len(ran) != len(pending) {
		t.Fatalf("ran %d migrations, expected %d", len(ran), len(pending))
	}

	// Idempotent.
	ran, err = Migrate(ctx, db)
	if err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if len(ran) != 0 {
		t.Fatalf("second migrate applied %v, expected none", ran)
	}

	// A few schema constraints that the rest of the system depends on.
	for _, table := range []string{"users", "user_roles", "credentials", "targets", "autoscaling_groups", "asg_instances", "access_policies", "access_sessions", "recordings", "audit_events", "key_versions"} {
		if _, err := db.ExecContext(ctx, "SELECT 1 FROM "+table+" WHERE 1=0"); err != nil { // #nosec G701 -- test constant
			t.Errorf("table %s missing: %v", table, err)
		}
	}
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO user_roles (user_id, role) VALUES (?, ?)`), "nobody", "superuser"); err == nil {
		t.Error("expected CHECK constraint on user_roles.role to reject 'superuser'")
	}
}

func TestMigrateSQLite(t *testing.T) {
	db := openTestDB(t, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	runMigrationSuite(t, db)
}

func TestMigratePostgres(t *testing.T) {
	dsn := os.Getenv("ZANSKAR_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ZANSKAR_TEST_POSTGRES_DSN not set")
	}
	db := openTestDB(t, config.DriverPostgres, dsn)
	ctx := context.Background()
	// Start from a clean schema so the test is repeatable.
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	runMigrationSuite(t, db)
}

func TestRebind(t *testing.T) {
	pg := &DB{Driver: config.DriverPostgres}
	if got := pg.Rebind("a = ? AND b = ?"); got != "a = $1 AND b = $2" {
		t.Fatalf("got %q", got)
	}
	lite := &DB{Driver: config.DriverSQLite}
	if got := lite.Rebind("a = ?"); got != "a = ?" {
		t.Fatalf("got %q", got)
	}
}
