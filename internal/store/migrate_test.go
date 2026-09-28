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

// TestSQLiteRebuildKeepsTargetHistory drives 0012_retire_targets over data
// laid down by the earlier schema: the rebuild must keep every session's link
// to its target, group and instance, keep credential bindings, put foreign
// keys back on, and afterwards let a retired name be enrolled again while a
// live name stays unique.
func TestSQLiteRebuildKeepsTargetHistory(t *testing.T) {
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
	const rebuild = "0012_retire_targets"
	for _, name := range names {
		version := strings.TrimSuffix(path.Base(name), ".sql")
		if version >= rebuild {
			break
		}
		body, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			t.Fatal(err)
		}
		if err := applyWithDirectives(ctx, db, version, string(body)); err != nil {
			t.Fatal(err)
		}
	}
	now := TimeArg(time.Now())
	for _, q := range []string{
		`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1', 'alice', 'Alice', ?, ?)`,
		`INSERT INTO credentials (id, name, type, mode, created_at, updated_at) VALUES ('c1', 'key', 'ssh_key', 'vaulted', ?, ?)`,
		`INSERT INTO targets (id, name, address, os_family, engine, created_at, updated_at) VALUES ('t1', 'box', '10.0.0.5', 'linux', NULL, ?, ?)`,
		`INSERT INTO target_credentials (target_id, protocol, credential_id) VALUES ('t1', 'ssh', 'c1')`,
		`INSERT INTO autoscaling_groups (id, name, provider, region, external_name, role_arn, external_id, os_family, created_at, updated_at) VALUES ('a1', 'fleet', 'aws', 'ap-south-1', 'fleet-asg', 'arn:aws:iam::1:role/r', 'ext', 'linux', ?, ?)`,
		`INSERT INTO asg_credentials (asg_id, protocol, credential_id) VALUES ('a1', 'ssh', 'c1')`,
		`INSERT INTO asg_instances (id, asg_id, instance_id, lifecycle_state, first_seen_at, last_seen_at) VALUES ('i1', 'a1', 'i-abc', 'InService', ?, ?)`,
		`INSERT INTO access_sessions (id, user_id, target_id, protocol, client_ip, started_at) VALUES ('s1', 'u1', 't1', 'ssh', '10.0.0.1', ?)`,
		`INSERT INTO access_sessions (id, user_id, asg_id, asg_instance_id, protocol, client_ip, started_at) VALUES ('s2', 'u1', 'a1', 'i1', 'ssh', '10.0.0.1', ?)`,
	} {
		args := []any{now, now}
		if strings.Contains(q, "access_sessions") {
			args = []any{now}
		}
		if !strings.Contains(q, "?") {
			args = nil
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
	var fk int
	if err := db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Fatalf("foreign keys must be back on after the rebuild: %d %v", fk, err)
	}
	var tname, gname, iname string
	if err := db.QueryRowContext(ctx, `SELECT t.name FROM access_sessions s JOIN targets t ON t.id = s.target_id WHERE s.id = 's1'`).Scan(&tname); err != nil || tname != "box" {
		t.Fatalf("session lost its target across the rebuild: %q %v", tname, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT g.name, i.instance_id FROM access_sessions s JOIN autoscaling_groups g ON g.id = s.asg_id JOIN asg_instances i ON i.id = s.asg_instance_id WHERE s.id = 's2'`).Scan(&gname, &iname); err != nil || gname != "fleet" || iname != "i-abc" {
		t.Fatalf("session lost its group or instance across the rebuild: %q %q %v", gname, iname, err)
	}
	var bindings int
	if err := db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM target_credentials) + (SELECT COUNT(*) FROM asg_credentials)`).Scan(&bindings); err != nil || bindings != 2 {
		t.Fatalf("credential bindings lost across the rebuild: %d %v", bindings, err)
	}

	// A live name is unique; a retired one is free.
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t2', 'box', '10.0.0.6', 'linux', ?, ?)`), now, now); err == nil {
		t.Fatal("a second live target named box must be refused")
	}
	if _, err := db.ExecContext(ctx, db.Rebind(`UPDATE targets SET deleted_at = ? WHERE id = 't1'`), now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t2', 'box', '10.0.0.6', 'linux', ?, ?)`), now, now); err != nil {
		t.Fatalf("re-enrolling a retired name: %v", err)
	}
	if _, err := db.ExecContext(ctx, db.Rebind(`UPDATE autoscaling_groups SET deleted_at = ? WHERE id = 'a1'`), now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO autoscaling_groups (id, name, provider, region, external_name, role_arn, external_id, os_family, created_at, updated_at) VALUES ('a2', 'fleet', 'aws', 'ap-south-1', 'fleet-asg', 'arn:aws:iam::1:role/r', 'ext', 'linux', ?, ?)`), now, now); err != nil {
		t.Fatalf("re-enrolling a retired group name: %v", err)
	}
}
