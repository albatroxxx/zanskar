// SPDX-License-Identifier: Apache-2.0

// Package storetest opens the database tests run against: SQLite in memory,
// migrated, closed when the test ends. It replaces a dozen copies of the
// same ten lines (D13).
package storetest

import (
	"context"
	"testing"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
)

// Open returns a fresh, migrated in-memory SQLite database, closed at the
// end of the test. Foreign keys are on, as in production.
func Open(tb testing.TB) *store.DB {
	tb.Helper()
	return openSQLite(tb, "")
}

func openSQLite(tb testing.TB, last string) *store.DB {
	tb.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = db.Close() })
	if _, err := store.MigrateTo(ctx, db, last); err != nil {
		tb.Fatal(err)
	}
	return db
}
