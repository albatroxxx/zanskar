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
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/migrations"
)

// Step is a migration written in Go, for a change SQL cannot make portably
// on both engines (ADR 0036: stored policies rewritten into a new shape). It
// runs in version order among the SQL files, in its own transaction, and is
// recorded in schema_migrations like a file.
type Step struct {
	Version string
	Run     func(ctx context.Context, db *DB, tx *sql.Tx) error
}

var (
	stepsMu sync.Mutex
	steps   = map[string]Step{}
)

// RegisterStep adds a step to every migration from now on. The package that
// owns the data registers its step when it is loaded, as database/sql
// drivers register, so no caller of Migrate can run the files without it.
// Registering the same version twice panics.
func RegisterStep(s Step) {
	stepsMu.Lock()
	defer stepsMu.Unlock()
	if s.Version == "" || s.Run == nil {
		panic("store: RegisterStep needs a version and a function")
	}
	if _, dup := steps[s.Version]; dup {
		panic("store: step " + s.Version + " registered twice")
	}
	steps[s.Version] = s
}

// migration is one entry of the ordered set: a SQL file or a Go step.
type migration struct {
	version string
	file    string
	step    *Step
}

// all lists the driver's SQL files and the registered steps in version order.
func all(driver string) ([]migration, error) {
	names, err := fs.Glob(migrations.FS, path.Join(driver, "*.sql"))
	if err != nil {
		return nil, fmt.Errorf("migrate: glob: %w", err)
	}
	var out []migration
	for _, name := range names {
		out = append(out, migration{version: strings.TrimSuffix(path.Base(name), ".sql"), file: name})
	}
	stepsMu.Lock()
	for _, s := range steps {
		s := s
		out = append(out, migration{version: s.Version, step: &s})
	}
	stepsMu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// Migrate applies every embedded migration for the DB's driver, and every
// registered step, that has not been applied yet, each in its own
// transaction, in lexical order of version. It returns the versions applied
// in this run.
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

	list, err := all(db.Driver)
	if err != nil {
		return nil, err
	}
	var ran []string
	for _, m := range list {
		if applied[m.version] {
			continue
		}
		if m.step != nil {
			if err := applyStep(ctx, db, *m.step); err != nil {
				return ran, err
			}
			ran = append(ran, m.version)
			continue
		}
		body, err := fs.ReadFile(migrations.FS, m.file)
		if err != nil {
			return ran, fmt.Errorf("migrate: read %s: %w", m.file, err)
		}
		if err := applyWithDirectives(ctx, db, m.version, string(body)); err != nil {
			return ran, err
		}
		ran = append(ran, m.version)
	}
	return ran, nil
}

// applyStep runs a Go step in its own transaction and records it.
func applyStep(ctx context.Context, db *DB, s Step) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrate %s: begin: %w", s.Version, err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = s.Run(ctx, db, tx); err != nil {
		return fmt.Errorf("migrate %s: %w", s.Version, err)
	}
	if err = record(ctx, db, tx, s.Version); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("migrate %s: commit: %w", s.Version, err)
	}
	return nil
}

func record(ctx context.Context, db *DB, tx *sql.Tx, version string) error {
	_, err := tx.ExecContext(ctx, db.Rebind(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`), // #nosec G701 -- constant statement, bound args
		version, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("migrate %s: record: %w", version, err)
	}
	return nil
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
	list, err := all(db.Driver)
	if err != nil {
		return nil, err
	}
	var pending []string
	for _, m := range list {
		if !applied[m.version] {
			pending = append(pending, m.version)
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
	if err = record(ctx, db, tx, version); err != nil {
		return err
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
