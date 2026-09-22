// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/migrations"
)

// Migrate applies every embedded migration for the DB's driver that has not
// been applied yet, each in its own transaction, in lexical order. It returns
// the names applied in this run.
func Migrate(ctx context.Context, db *DB) ([]string, error) {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return nil, fmt.Errorf("migrate: create schema_migrations: %w", err)
	}

	applied, err := appliedVersions(ctx, db)
	if err != nil {
		return nil, err
	}

	names, err := fs.Glob(migrations.FS, path.Join(db.Driver, "*.sql"))
	if err != nil {
		return nil, fmt.Errorf("migrate: glob: %w", err)
	}
	sort.Strings(names)

	var ran []string
	for _, name := range names {
		version := strings.TrimSuffix(path.Base(name), ".sql")
		if applied[version] {
			continue
		}
		body, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return ran, fmt.Errorf("migrate: read %s: %w", name, err)
		}
		if err := applyWithDirectives(ctx, db, version, string(body)); err != nil {
			return ran, err
		}
		ran = append(ran, version)
	}
	return ran, nil
}

// fkOffDirective, on the first line of a SQLite migration, asks for foreign
// keys to be off while it runs. SQLite cannot alter a column in place, so such
// a migration rebuilds a table; with foreign keys on, its DROP TABLE would
// cascade into every row that references the table. The pragma cannot change
// inside a transaction, so it is toggled around the migration's own
// transaction on the single connection SQLite uses, and the schema is checked
// for dangling references before foreign keys are enabled again.
const fkOffDirective = "-- migrate: foreign_keys=off"

func applyWithDirectives(ctx context.Context, db *DB, version, body string) error {
	if db.Driver != config.DriverSQLite || !strings.HasPrefix(body, fkOffDirective) {
		return applyOne(ctx, db, version, body)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		return fmt.Errorf("migrate %s: foreign_keys off: %w", version, err)
	}
	err := applyOne(ctx, db, version, body)
	if _, e := db.ExecContext(ctx, `PRAGMA foreign_keys=ON`); e != nil && err == nil {
		err = fmt.Errorf("migrate %s: foreign_keys on: %w", version, e)
	}
	if err != nil {
		return err
	}
	rows, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("migrate %s: foreign_key_check: %w", version, err)
	}
	defer func() { _ = rows.Close() }()
	if rows.Next() {
		return fmt.Errorf("migrate %s: rebuild left dangling foreign keys", version)
	}
	return rows.Err()
}

// Pending reports the migration versions not yet applied.
func Pending(ctx context.Context, db *DB) ([]string, error) {
	applied, err := appliedVersions(ctx, db)
	if err != nil {
		if isMissingTable(err) {
			applied = map[string]bool{}
		} else {
			return nil, err
		}
	}
	names, err := fs.Glob(migrations.FS, path.Join(db.Driver, "*.sql"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var pending []string
	for _, name := range names {
		v := strings.TrimSuffix(path.Base(name), ".sql")
		if !applied[v] {
			pending = append(pending, v)
		}
	}
	return pending, nil
}

func applyOne(ctx context.Context, db *DB, version, body string) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrate %s: begin: %w", version, err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	// body comes from the embedded migration set, not from any input.
	if _, err = tx.ExecContext(ctx, body); err != nil { // #nosec G701
		return fmt.Errorf("migrate %s: exec: %w", version, err)
	}
	_, err = tx.ExecContext(ctx, db.Rebind(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`), // #nosec G701 -- constant statement, bound args
		version, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("migrate %s: record: %w", version, err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("migrate %s: commit: %w", version, err)
	}
	return nil
}

func appliedVersions(ctx context.Context, db *DB) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("migrate: read applied: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}

func isMissingTable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no such table") || strings.Contains(msg, "does not exist") || errors.Is(err, sql.ErrNoRows)
}
