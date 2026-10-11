// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/albatroxxx/zanskar/internal/config"
)

// runConstraintSuite makes each engine fail each kind of constraint and checks
// that exactly the matching helper recognises it, by the driver's code. The
// repos turn these into 409s and 400s; a miss there is a 500 (M23).
func runConstraintSuite(t *testing.T, db *DB) {
	ctx := context.Background()
	// One connection throughout: a Postgres temporary table exists only on
	// the connection that created it.
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	exec := func(q string, args ...any) error {
		_, err := conn.ExecContext(ctx, db.Rebind(q), args...)
		return err
	}
	for _, q := range []string{
		`CREATE TEMPORARY TABLE zz_parent (id TEXT PRIMARY KEY, name TEXT UNIQUE, n INTEGER CHECK (n > 0))`,
		`CREATE TEMPORARY TABLE zz_child (id TEXT PRIMARY KEY, parent_id TEXT REFERENCES zz_parent (id))`,
	} {
		if err := exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := exec(`INSERT INTO zz_parent (id, name, n) VALUES (?, ?, ?)`, "p1", "a", 1); err != nil {
		t.Fatal(err)
	}
	if err := exec(`INSERT INTO zz_child (id, parent_id) VALUES (?, ?)`, "c1", "p1"); err != nil {
		t.Fatal(err)
	}

	type want struct{ unique, fk, check bool }
	cases := []struct {
		name string
		err  error
		want want
	}{
		{"unique column", exec(`INSERT INTO zz_parent (id, name, n) VALUES (?, ?, ?)`, "p2", "a", 1), want{unique: true}},
		{"primary key", exec(`INSERT INTO zz_parent (id, name, n) VALUES (?, ?, ?)`, "p1", "b", 1), want{unique: true}},
		{"missing parent", exec(`INSERT INTO zz_child (id, parent_id) VALUES (?, ?)`, "c2", "nobody"), want{fk: true}},
		{"parent still referenced", exec(`DELETE FROM zz_parent WHERE id = ?`, "p1"), want{fk: true}},
		{"check", exec(`INSERT INTO zz_parent (id, name, n) VALUES (?, ?, ?)`, "p3", "c", 0), want{check: true}},
		{"syntax", exec(`INSERT INTO zz_nowhere VALUES (1)`), want{}},
		{"no rows", sql.ErrNoRows, want{}},
		{"none", nil, want{}},
		// A message that names a constraint is not one.
		{"lookalike", errors.New("UNIQUE constraint failed: duplicate key value violates foreign key constraint, CHECK constraint failed"), want{}},
	}
	for _, c := range cases {
		if c.want != (want{}) && c.err == nil {
			t.Errorf("%s: the statement succeeded, want a constraint error", c.name)
			continue
		}
		for _, err := range []error{c.err, fmt.Errorf("wrapped: %w", c.err)} {
			if c.err == nil && err != nil {
				continue
			}
			got := want{IsUniqueViolation(err), IsForeignKeyViolation(err), IsCheckViolation(err)}
			if got != c.want {
				t.Errorf("%s (%v): got %+v, want %+v", c.name, err, got, c.want)
			}
		}
	}
}

func TestConstraintErrorsSQLite(t *testing.T) {
	runConstraintSuite(t, openTestDB(t, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)"))
}

func TestConstraintErrorsPostgres(t *testing.T) {
	dsn := os.Getenv("ZANSKAR_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ZANSKAR_TEST_POSTGRES_DSN not set")
	}
	runConstraintSuite(t, openTestDB(t, config.DriverPostgres, dsn))
}
