// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/migrations"
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

// TestSQLiteRebuildKeepsSessionPolicyLinks applies the schema up to the
// migration before the access_policies rebuild, seeds a policy and a session
// that references it, then runs the rebuild. The session must keep its
// policy_id: with foreign keys left on, DROP TABLE would have nulled it.
func TestSQLiteRebuildKeepsSessionPolicyLinks(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	names, err := fs.Glob(migrations.FS, "sqlite/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	const rebuild = "0006_policy_user_subject"
	for _, name := range names {
		version := strings.TrimSuffix(path.Base(name), ".sql")
		if version >= rebuild {
			break
		}
		body, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			t.Fatal(err)
		}
		if err := applyOne(ctx, db, version, string(body)); err != nil {
			t.Fatal(err)
		}
	}
	now := TimeArg(time.Now())
	for _, q := range []string{
		`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1', 'alice', 'Alice', ?, ?)`,
		`INSERT INTO groups (id, name, created_at, updated_at) VALUES ('g1', 'ops', ?, ?)`,
		`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t1', 'box', '10.0.0.5', 'linux', ?, ?)`,
		`INSERT INTO access_policies (id, name, group_id, target_selector, protocols, created_at, updated_at) VALUES ('p1', 'ops-ssh', 'g1', '{"tags":{"env":"prod"}}', '["ssh"]', ?, ?)`,
		`INSERT INTO access_sessions (id, user_id, policy_id, target_id, protocol, client_ip, started_at) VALUES ('s1', 'u1', 'p1', 't1', 'ssh', '10.0.0.1', ?)`,
	} {
		args := []any{now, now}
		if strings.Contains(q, "access_sessions") {
			args = []any{now}
		}
		if _, err := db.ExecContext(ctx, db.Rebind(q), args...); err != nil {
			t.Fatalf("%s: %v", q[:40], err)
		}
	}

	ran, err := Migrate(ctx, db)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if len(ran) == 0 || ran[0] != rebuild {
		t.Fatalf("expected the rebuild to run first, ran %v", ran)
	}

	var policyID string
	if err := db.QueryRowContext(ctx, `SELECT policy_id FROM access_sessions WHERE id = 's1'`).Scan(&policyID); err != nil || policyID != "p1" {
		t.Fatalf("session lost its policy link across the rebuild: %q %v", policyID, err)
	}
	var fk int
	if err := db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Fatalf("foreign keys must be back on after the rebuild: %d %v", fk, err)
	}
	// The new shape: a user-bound policy is accepted, a policy with neither or
	// both subjects is refused by the CHECK constraint.
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO access_policies (id, name, user_id, target_selector, protocols, created_at, updated_at) VALUES ('p2', 'alice-only', 'u1', '{"targets":["t1"]}', '["ssh"]', ?, ?)`), now, now); err != nil {
		t.Fatalf("user-bound policy: %v", err)
	}
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO access_policies (id, name, target_selector, protocols, created_at, updated_at) VALUES ('p3', 'nobody', '{}', '["ssh"]', ?, ?)`), now, now); err == nil {
		t.Fatal("a policy with no subject must be rejected")
	}
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO access_policies (id, name, group_id, user_id, target_selector, protocols, created_at, updated_at) VALUES ('p4', 'both', 'g1', 'u1', '{}', '["ssh"]', ?, ?)`), now, now); err == nil {
		t.Fatal("a policy with two subjects must be rejected")
	}
}
