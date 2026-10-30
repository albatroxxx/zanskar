// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"

	"github.com/albatroxxx/zanskar/internal/config"
)

// withSteps runs the test with exactly these steps registered, and puts the
// package's own back afterwards.
func withSteps(t *testing.T, list ...Step) {
	t.Helper()
	stepsMu.Lock()
	saved := steps
	steps = map[string]Step{}
	stepsMu.Unlock()
	for _, s := range list {
		RegisterStep(s)
	}
	t.Cleanup(func() {
		stepsMu.Lock()
		steps = saved
		stepsMu.Unlock()
	})
}

func memDB(t *testing.T) *DB {
	t.Helper()
	return openTestDB(t, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
}

// TestStepRunsOnceInOrder (ADR 0036): a Go step runs between the files that
// sort around it, sees the schema they leave, is recorded and listed as
// pending like a file, and does not run again.
func TestStepRunsOnceInOrder(t *testing.T) {
	runs := 0
	withSteps(t, Step{Version: "0001_zz_test_step", Run: func(ctx context.Context, db *DB, tx *sql.Tx) error {
		runs++
		// 0001 has run, 0002 has not: 0002 adds the lower(username) index.
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			return err
		}
		var idx int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND sql LIKE '%lower(username)%'`).Scan(&idx); err != nil {
			return err
		}
		if idx != 0 {
			return errors.New("0002 ran before the step")
		}
		return nil
	}})
	db := memDB(t)
	ctx := context.Background()
	pending, err := Pending(ctx, db)
	if err != nil || !slices.Contains(pending, "0001_zz_test_step") || pending[1] != "0001_zz_test_step" {
		t.Fatalf("pending: %v %v", pending, err)
	}
	ran, err := Migrate(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if runs != 1 || ran[1] != "0001_zz_test_step" {
		t.Fatalf("runs %d, ran %v", runs, ran[:3])
	}
	if again, err := Migrate(ctx, db); err != nil || len(again) != 0 || runs != 1 {
		t.Fatalf("a second run: %v %v, runs %d", again, err, runs)
	}
	if pending, _ := Pending(ctx, db); len(pending) != 0 {
		t.Fatalf("still pending: %v", pending)
	}
}

// TestStepFailureStopsTheRun: a step that fails rolls back what it wrote,
// is not recorded, and stops the files after it.
func TestStepFailureStopsTheRun(t *testing.T) {
	withSteps(t, Step{Version: "0001_zz_test_step", Run: func(ctx context.Context, db *DB, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `CREATE TABLE step_scratch (x INTEGER)`); err != nil {
			return err
		}
		return errors.New("refused")
	}})
	db := memDB(t)
	ctx := context.Background()
	ran, err := Migrate(ctx, db)
	if err == nil || len(ran) != 1 || ran[0] != "0001_init" {
		t.Fatalf("ran %v, err %v; want 0001_init then the failure", ran, err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE name = 'step_scratch'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the failed step's table survived: %d %v", n, err)
	}
	if pending, _ := Pending(ctx, db); len(pending) == 0 || pending[0] != "0001_zz_test_step" {
		t.Fatalf("the failed step is not pending first: %v", pending)
	}
}

// TestRegisterStepRefusesDuplicates: two owners of one version is a bug.
func TestRegisterStepRefusesDuplicates(t *testing.T) {
	withSteps(t, Step{Version: "0001_zz_test_step", Run: func(context.Context, *DB, *sql.Tx) error { return nil }})
	defer func() {
		if recover() == nil {
			t.Fatal("a second registration of one version did not panic")
		}
	}()
	RegisterStep(Step{Version: "0001_zz_test_step", Run: func(context.Context, *DB, *sql.Tx) error { return nil }})
}
