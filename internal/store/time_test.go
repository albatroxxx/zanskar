// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
)

// TestTimeArgSortsAsTime pins the stored form (M28). SQLite keeps timestamps
// as TEXT and compares them byte by byte, so text order must be time order.
// RFC 3339 with its trailing zeros trimmed is not: "…T10:00:00.5Z" sorted
// before "…T10:00:00Z", because '.' < 'Z'.
func TestTimeArgSortsAsTime(t *testing.T) {
	base := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	ist := time.FixedZone("IST", 5*3600+1800)
	for _, c := range []struct {
		in   time.Time
		want string
	}{
		{base, "2026-10-11T10:00:00.000000Z"},
		{base.Add(500 * time.Millisecond), "2026-10-11T10:00:00.500000Z"},
		{base.Add(time.Microsecond), "2026-10-11T10:00:00.000001Z"},
		// Truncated to the microsecond PostgreSQL keeps, never rounded.
		{base.Add(999 * time.Nanosecond), "2026-10-11T10:00:00.000000Z"},
		{base.Add(123456789 * time.Nanosecond), "2026-10-11T10:00:00.123456Z"},
		// Always written in UTC.
		{time.Date(2026, 10, 11, 15, 30, 0, 250_000_000, ist), "2026-10-11T10:00:00.250000Z"},
	} {
		if got := TimeArg(c.in); got != c.want {
			t.Errorf("TimeArg(%v) = %q, want %q", c.in, got, c.want)
		}
	}

	// Instants in time order, crowded around two second boundaries.
	ordered := []time.Time{
		base.Add(-time.Microsecond),
		base,
		base.Add(time.Microsecond),
		base.Add(500 * time.Millisecond),
		base.Add(time.Second - time.Microsecond),
		base.Add(time.Second),
		base.Add(1500 * time.Millisecond),
	}
	for i, in := range ordered {
		s := TimeArg(in)
		if len(s) != len("2006-01-02T15:04:05.000000Z") {
			t.Errorf("TimeArg(%v) = %q is not fixed width", in, s)
		}
		if i > 0 {
			if prev := TimeArg(ordered[i-1]); prev >= s {
				t.Errorf("text order differs from time order: %q is not before %q", prev, s)
			}
		}
	}
}

// TestNullTimeReadsOldAndNewForms: rows written before migration 0030, and by
// any build before it, hold RFC 3339 with trimmed zeros (or whole seconds,
// from the key ring); they must still read. NullTime writes the fixed form.
func TestNullTimeReadsOldAndNewForms(t *testing.T) {
	base := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		in     string
		want   time.Time
		stored string // what Value writes back
	}{
		{"2026-10-11T10:00:00Z", base, "2026-10-11T10:00:00.000000Z"},
		{"2026-10-11T10:00:00.5Z", base.Add(500 * time.Millisecond), "2026-10-11T10:00:00.500000Z"},
		{"2026-10-11T10:00:00.123456789Z", base.Add(123456789 * time.Nanosecond), "2026-10-11T10:00:00.123456Z"},
		{"2026-10-11T10:00:00.000000Z", base, "2026-10-11T10:00:00.000000Z"},
		{"2026-10-11T10:00:00.500000Z", base.Add(500 * time.Millisecond), "2026-10-11T10:00:00.500000Z"},
	} {
		for _, src := range []any{c.in, []byte(c.in)} {
			var n NullTime
			if err := n.Scan(src); err != nil || !n.Valid || !n.Time.Equal(c.want) || n.Time.Location() != time.UTC {
				t.Errorf("Scan(%T %q) = %v %v %v, want %v", src, c.in, n.Time, n.Valid, err, c.want)
			}
			// Written back, every form becomes the fixed one.
			if v, err := n.Value(); err != nil || v != c.stored {
				t.Errorf("Value after Scan(%q) = %v %v, want %q", c.in, v, err, c.stored)
			}
		}
	}
	var n NullTime
	if err := n.Scan(base.In(time.FixedZone("x", 3600))); err != nil || !n.Valid || !n.Time.Equal(base) || n.Time.Location() != time.UTC {
		t.Errorf("Scan(time.Time) = %v %v %v", n.Time, n.Valid, err)
	}
	if err := n.Scan(nil); err != nil || n.Valid {
		t.Errorf("Scan(nil) = %v %v", n.Valid, err)
	}
	if v, err := n.Value(); err != nil || v != nil {
		t.Errorf("Value of a NULL = %v %v", v, err)
	}
	if err := n.Scan("yesterday"); err == nil {
		t.Error("Scan of a non-time must fail")
	}
}

// TestTimestampsCompareAsTimes runs the comparisons the application makes
// (ORDER BY, >=, <) on a real timestamp column, on SQLite and, when
// ZANSKAR_TEST_POSTGRES_DSN is set, on PostgreSQL: both engines must answer
// alike inside a shared second (ADR 0003).
func TestTimestampsCompareAsTimes(t *testing.T) {
	base := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	for _, b := range testBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			db := b.open(t)
			if _, err := Migrate(ctx, db); err != nil {
				t.Fatal(err)
			}
			for sink, at := range map[string]time.Time{
				"whole":     base,
				"half":      base.Add(500 * time.Millisecond),
				"next":      base.Add(time.Second),
				"next-half": base.Add(1500 * time.Millisecond),
			} {
				if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO audit_export_state (sink, last_id, updated_at) VALUES (?, 0, ?)`), sink, TimeArg(at)); err != nil {
					t.Fatal(err)
				}
			}
			sinks := func(where string, args ...any) []string {
				t.Helper()
				rows, err := db.QueryContext(ctx, db.Rebind(`SELECT sink FROM audit_export_state `+where+` ORDER BY updated_at`), args...) // #nosec G202 -- test constants
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = rows.Close() }()
				var out []string
				for rows.Next() {
					var s string
					if err := rows.Scan(&s); err != nil {
						t.Fatal(err)
					}
					out = append(out, s)
				}
				if err := rows.Err(); err != nil {
					t.Fatal(err)
				}
				return out
			}
			for _, c := range []struct {
				where string
				arg   time.Time
				want  []string
			}{
				{"", time.Time{}, []string{"whole", "half", "next", "next-half"}},
				{"WHERE updated_at >= ?", base, []string{"whole", "half", "next", "next-half"}},
				{"WHERE updated_at > ?", base, []string{"half", "next", "next-half"}},
				{"WHERE updated_at < ?", base.Add(time.Second), []string{"whole", "half"}},
				{"WHERE updated_at <= ?", base.Add(time.Second), []string{"whole", "half", "next"}},
				{"WHERE updated_at > ?", base.Add(500 * time.Millisecond), []string{"next", "next-half"}},
			} {
				var args []any
				if c.where != "" {
					args = append(args, TimeArg(c.arg))
				}
				if got := sinks(c.where, args...); !slices.Equal(got, c.want) {
					t.Errorf("%q with %s: got %q, want %q", c.where, TimeArg(c.arg), got, c.want)
				}
			}
		})
	}
}

type testBackend struct {
	name string
	open func(t *testing.T) *DB
}

// testBackends is SQLite in memory and, when ZANSKAR_TEST_POSTGRES_DSN is
// set, PostgreSQL in a schema of the test's own, dropped afterwards.
func testBackends(t *testing.T) []testBackend {
	t.Helper()
	backends := []testBackend{{"sqlite", func(t *testing.T) *DB {
		return openTestDB(t, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	}}}
	if dsn := os.Getenv("ZANSKAR_TEST_POSTGRES_DSN"); dsn != "" {
		backends = append(backends, testBackend{"postgres", func(t *testing.T) *DB { return isolatedPostgres(t, dsn) }})
	}
	return backends
}

func isolatedPostgres(t *testing.T, dsn string) *DB {
	t.Helper()
	ctx := context.Background()
	admin := openTestDB(t, config.DriverPostgres, dsn)
	var b [6]byte
	_, _ = rand.Read(b[:])
	schema := "store_test_" + hex.EncodeToString(b[:])
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`) })
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return openTestDB(t, config.DriverPostgres, u.String())
}
