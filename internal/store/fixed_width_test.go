// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/migrations"
)

// FixedWidthMigration is the migration that rewrites every stored SQLite
// timestamp to the form TimeArg writes (M28). It is exported, as is
// FixedWidthRewrites, for the migration test in package store_test.
const FixedWidthMigration = "0030_fixed_width_timestamps"

// rewriteStatement matches one column rewrite in the fixed-width migration.
var rewriteStatement = regexp.MustCompile(`(?m)^UPDATE (\w+) SET (\w+) =`)

// notRewritten lists the timestamp-looking SQLite columns the fixed-width
// migration leaves alone, each with the reason. A timestamp column created by
// a later migration has no rows from before the rewrite: it belongs here,
// saying so, provided every value it holds is written through TimeArg.
var notRewritten = map[string]string{
	"schema_migrations.applied_at": "the migrator's own bookkeeping, TEXT on both engines, written as RFC 3339 whole seconds (one width already) and never read or compared",
	"app_sessions.expires_at":      "created by migration 0031, after the fixed-width form; every row is written through store.TimeArg",
	"app_sessions.created_at":      "created by migration 0031, after the fixed-width form; every row is written through store.TimeArg",
	"app_sessions.last_seen_at":    "created by migration 0031, after the fixed-width form; every row is written through store.TimeArg",
}

// TestEveryTimestampColumnIsRewritten fails when the migrated SQLite schema
// holds a column that reads as a timestamp but is neither rewritten by the
// fixed-width migration nor listed in notRewritten, so a timestamp column
// cannot miss the rewrite unnoticed: its old rows would keep comparing as
// trimmed text.
func TestEveryTimestampColumnIsRewritten(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if _, err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	rewritten := map[string]bool{}
	for _, key := range FixedWidthRewrites(t) {
		rewritten[key] = true
	}

	type column struct{ table, name, typ string }
	var columns []column
	rows, err := db.QueryContext(ctx, `SELECT m.name, p.name, p.type FROM sqlite_master m JOIN pragma_table_info(m.name) p
		WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite!_%' ESCAPE '!' ORDER BY m.name, p.cid`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var c column
		if err := rows.Scan(&c.table, &c.name, &c.typ); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for _, c := range columns {
		key := c.table + "." + c.name
		seen[key] = true
		if !timestampLike(c.name) || numericAffinity(c.typ) {
			if rewritten[key] {
				t.Errorf("%s is rewritten by %s but is not a text timestamp column", key, FixedWidthMigration)
			}
			continue
		}
		_, excluded := notRewritten[key]
		switch {
		case rewritten[key] && excluded:
			t.Errorf("%s is both rewritten by %s and listed in notRewritten", key, FixedWidthMigration)
		case !rewritten[key] && !excluded:
			t.Errorf("%s reads as a timestamp but %s does not rewrite it: add an UPDATE for it there "+
				"(the column existed before it ran), or list it in notRewritten with the reason", key, FixedWidthMigration)
		}
	}
	for key := range notRewritten {
		if !seen[key] {
			t.Errorf("notRewritten lists %s, which is not in the schema", key)
		}
	}
}

// FixedWidthRewrites returns "table.column" for every column the SQLite
// fixed-width migration rewrites, read from the migration itself, after
// checking that both migration sets have it. It is exported for the
// migration test in package store_test.
func FixedWidthRewrites(t testing.TB) []string {
	t.Helper()
	var out []string
	for _, driver := range []string{config.DriverPostgres, config.DriverSQLite} {
		body, err := fs.ReadFile(migrations.FS, driver+"/"+FixedWidthMigration+".sql")
		if err != nil {
			t.Fatalf("the %s migration %s: %v", driver, FixedWidthMigration, err)
		}
		if driver == config.DriverSQLite {
			for _, m := range rewriteStatement.FindAllStringSubmatch(string(body), -1) {
				out = append(out, m[1]+"."+m[2])
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("found no column rewrites in %s", FixedWidthMigration)
	}
	return out
}

// timestampLike reports whether a column name reads as a point in time.
func timestampLike(name string) bool {
	switch name[strings.LastIndex(name, "_")+1:] {
	case "at", "until", "ts", "time", "timestamp", "date", "on", "seen", "created", "updated", "expires", "expiry":
		return true
	}
	return false
}

// numericAffinity reports whether SQLite stores a declared type as a number
// (an epoch value compares correctly as one): INTEGER, REAL, FLOAT, DOUBLE.
func numericAffinity(typ string) bool {
	typ = strings.ToUpper(typ)
	for _, s := range []string{"INT", "REAL", "FLOAT", "DOUBLE"} {
		if strings.Contains(typ, s) {
			return true
		}
	}
	return false
}
