// SPDX-License-Identifier: Apache-2.0

package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
)

// PostgresDSN names the environment variable CI sets to run the Postgres leg.
const PostgresDSN = "ZANSKAR_TEST_POSTGRES_DSN"

// ForEachBackend runs fn as a subtest on SQLite in memory and, when
// ZANSKAR_TEST_POSTGRES_DSN is set (CI does this), on PostgreSQL in a schema
// of its own that is dropped afterwards. Both databases are migrated. It
// is the one place a repository test needs to touch to prove its queries
// on both engines: ON CONFLICT upserts, LOWER() lookups, LIKE ... ESCAPE,
// JSONB columns and TIMESTAMPTZ comparisons all differ between them.
func ForEachBackend(t *testing.T, fn func(t *testing.T, db *store.DB)) {
	t.Helper()
	ForEachBackendUpTo(t, "", fn)
}

// ForEachBackendUpTo is ForEachBackend with the databases migrated only up
// to version last, for a test that stores rows in an older schema and then
// watches the rest of the migrations convert them.
func ForEachBackendUpTo(t *testing.T, last string, fn func(t *testing.T, db *store.DB)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) { fn(t, openSQLite(t, last)) })
	dsn := os.Getenv(PostgresDSN)
	if dsn == "" {
		return
	}
	t.Run("postgres", func(t *testing.T) { fn(t, openPostgres(t, dsn, last)) })
}

var schemaChars = regexp.MustCompile(`[^a-z0-9_]+`)

// OpenPostgres opens dsn in a fresh schema named after the test plus a
// random suffix, migrates it and drops it at cleanup, so tests of different
// packages share no rows, no sequence and no advisory state through the one
// CI server. The migration test resets the public schema; nothing here uses
// it.
func OpenPostgres(tb testing.TB, dsn string) *store.DB {
	tb.Helper()
	return openPostgres(tb, dsn, "")
}

func openPostgres(tb testing.TB, dsn, last string) *store.DB {
	tb.Helper()
	ctx := context.Background()
	admin, err := store.Open(ctx, config.DriverPostgres, dsn)
	if err != nil {
		tb.Fatal(err)
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	name := schemaChars.ReplaceAllString(strings.ToLower(tb.Name()), "_")
	if len(name) > 40 {
		name = name[:40]
	}
	schema := "t_" + name + "_" + hex.EncodeToString(b[:])
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		_ = admin.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		tb.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := store.Open(ctx, config.DriverPostgres, u.String())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = db.Close() })
	if _, err := store.MigrateTo(ctx, db, last); err != nil {
		tb.Fatal(err)
	}
	return db
}
