// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
)

var fixedForm = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$`)

// TestFixedWidthMigration lays rows down the way builds before migration 0030
// wrote them on SQLite: RFC 3339 with trailing zeros trimmed (nanoseconds, as
// on Linux hosts), whole seconds from the key ring, and one audit event from a
// build that predates microsecond hashing. 0030 must leave every value in the
// fixed form at the same instant, keep the audit chain verifying, put text
// order right, and change nothing when run again.
func TestFixedWidthMigration(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	base := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	trimmed := func(d time.Duration) string { return base.Add(d).Format(time.RFC3339Nano) } // TimeArg before 0030
	seconds := func(d time.Duration) string { return base.Add(d).Format(time.RFC3339) }     // the key ring before 0030

	exec(`INSERT INTO users (id, username, display_name, created_at, updated_at, locked_until, last_login_at) VALUES ('u1', 'alice', 'Alice', ?, ?, ?, ?)`,
		trimmed(123456789*time.Nanosecond), trimmed(500*time.Millisecond), seconds(time.Hour), trimmed(123456700*time.Nanosecond))
	exec(`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t1', 'box', '10.0.0.5', 'linux', ?, ?)`,
		trimmed(0), trimmed(time.Microsecond))
	exec(`INSERT INTO key_versions (id, algorithm, kek_source, wrapped_dek, created_at, rotated_at) VALUES (1, 'aes-256-gcm', 'local', x'00', ?, ?)`,
		seconds(0), seconds(2*time.Hour))
	// Inside a shared second trimmed text sorts s2 before s1 and s4 before s3.
	starts := []struct {
		id string
		at time.Duration
	}{{"s1", 0}, {"s2", 500 * time.Millisecond}, {"s3", time.Second}, {"s4", 1500 * time.Millisecond}, {"s5", 1500*time.Millisecond + 1234*time.Nanosecond}}
	for i, s := range starts {
		ended := any(nil)
		if i%2 == 0 {
			ended = trimmed(s.at + 90*time.Second)
		}
		exec(`INSERT INTO access_sessions (id, user_id, target_id, protocol, client_ip, started_at, ended_at) VALUES (?, 'u1', 't1', 'ssh', '10.0.0.1', ?, ?)`,
			s.id, trimmed(s.at), ended)
	}
	retain := 30*24*time.Hour + 250*time.Millisecond
	exec(`INSERT INTO recordings (id, session_id, format, storage_uri, started_at, retention_until, created_at) VALUES ('r1', 's1', 'asciicast', 'file:///r1.cast', ?, ?, ?)`,
		trimmed(0), trimmed(retain), trimmed(0))

	// Audit events, linked and stored the way Record did before 0030. Since
	// v1.0.0 Record truncates to microseconds before hashing; the event
	// marked legacy is from a build before that, hashed over nanoseconds.
	events := []struct {
		at     time.Duration
		legacy bool
	}{{0, false}, {500 * time.Millisecond, false}, {700*time.Millisecond + time.Nanosecond, true}, {time.Second, false}, {1500 * time.Millisecond, false}, {2*time.Second + 123456*time.Microsecond, false}}
	prev := ""
	for _, ev := range events {
		e := audit.Event{Timestamp: base.Add(ev.at), ActorIP: "10.0.0.1", Action: "user.login", Outcome: audit.Success, Details: json.RawMessage(`{}`)}
		if !ev.legacy {
			e.Timestamp = e.Timestamp.Truncate(time.Microsecond)
		}
		if err := audit.Link(&e, prev); err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO audit_events (ts, actor_ip, action, outcome, details, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			e.Timestamp.UTC().Format(time.RFC3339Nano), e.ActorIP, e.Action, string(e.Outcome), string(e.Details), e.PrevHash, e.Hash)
		prev = e.Hash
	}
	log := audit.NewLog(db)
	if res, err := log.Verify(ctx, bytes.Repeat([]byte{9}, 32)); err != nil || res.Broken != nil || res.Checked != int64(len(events)) {
		t.Fatalf("the chain laid down must verify before the migration: %+v %v", res, err)
	}

	// read adds every value of one rewritten column to out, keyed by
	// "table.column#rowid". Its cursor is closed on return: SQLite has one
	// connection, and the next column's query needs it.
	read := func(out map[string]sql.NullString, key string) {
		t.Helper()
		table, column, _ := strings.Cut(key, ".")
		// Names come from the embedded migration, not from input.
		rows, err := db.QueryContext(ctx, `SELECT rowid, `+column+` FROM `+table) // #nosec G202
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id int64
			var v sql.NullString
			if err := rows.Scan(&id, &v); err != nil {
				t.Fatal(err)
			}
			out[key+"#"+strconv.FormatInt(id, 10)] = v
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	}
	columns := store.FixedWidthRewrites(t)
	snapshot := func() map[string]sql.NullString {
		t.Helper()
		out := map[string]sql.NullString{}
		for _, key := range columns {
			read(out, key)
		}
		return out
	}
	rerun := func() {
		t.Helper()
		exec(`DELETE FROM schema_migrations WHERE version = ?`, store.FixedWidthMigration)
		ran, err := store.Migrate(ctx, db)
		if err != nil || !slices.Equal(ran, []string{store.FixedWidthMigration}) {
			t.Fatalf("rerun %s: ran %v, %v", store.FixedWidthMigration, ran, err)
		}
	}

	before := snapshot()
	rerun()
	after := snapshot()

	checked := 0
	for key, old := range before {
		now := after[key]
		if !old.Valid {
			if now.Valid {
				t.Errorf("%s: NULL became %q", key, now.String)
			}
			continue
		}
		checked++
		was, err := time.Parse(time.RFC3339Nano, old.String)
		if err != nil {
			t.Fatalf("%s: seeded %q does not parse: %v", key, old.String, err)
		}
		if strings.HasPrefix(key, "audit_events.ts#") && fraction(old.String) > 6 {
			// Its hash covers every digit: left exactly as it was.
			if now.String != old.String {
				t.Errorf("%s: a pre-1.0 audit time was rewritten, %q to %q", key, old.String, now.String)
			}
			continue
		}
		is, err := time.Parse(time.RFC3339Nano, now.String)
		if !fixedForm.MatchString(now.String) || err != nil || !is.Equal(was.Truncate(time.Microsecond)) {
			t.Errorf("%s: %q became %q, want %s", key, old.String, now.String, store.TimeArg(was))
		}
	}
	// users 4, targets 2, key_versions 2, sessions 5 started and 3 ended,
	// recordings 3, audit events 6.
	if checked != 25 {
		t.Fatalf("checked %d seeded values, want 25", checked)
	}

	if res, err := log.Verify(ctx, bytes.Repeat([]byte{9}, 32)); err != nil || res.Broken != nil || res.Checked != int64(len(events)) || res.LastHash != prev {
		t.Fatalf("the audit chain must survive the rewrite: %+v %v", res, err)
	}

	ids := func(q string, args ...any) []string {
		t.Helper()
		rows, err := db.QueryContext(ctx, q, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			out = append(out, id)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := ids(`SELECT id FROM access_sessions ORDER BY started_at`); !slices.Equal(got, []string{"s1", "s2", "s3", "s4", "s5"}) {
		t.Errorf("sessions in start order: %v", got)
	}
	if got := ids(`SELECT id FROM access_sessions WHERE started_at >= ? AND started_at < ? ORDER BY started_at`,
		store.TimeArg(base), store.TimeArg(base.Add(time.Second))); !slices.Equal(got, []string{"s1", "s2"}) {
		t.Errorf("sessions started in the first second: %v", got)
	}
	if got := ids(`SELECT id FROM recordings WHERE retention_until <= ?`, store.TimeArg(base.Add(retain))); !slices.Equal(got, []string{"r1"}) {
		t.Errorf("a recording due at its retention time: %v", got)
	}
	for _, c := range []struct {
		f    audit.Filter
		want int
	}{
		{audit.Filter{From: base, To: base.Add(time.Second)}, 3},
		{audit.Filter{From: base.Add(time.Second)}, 3},
		{audit.Filter{From: base.Add(500 * time.Millisecond), To: base.Add(1500 * time.Millisecond)}, 3},
	} {
		if got, _, err := log.List(ctx, c.f); err != nil || len(got) != c.want {
			t.Errorf("audit events from %s to %s: %d %v, want %d", c.f.From, c.f.To, len(got), err, c.want)
		}
	}

	// Run again over its own output: nothing changes.
	rerun()
	if again := snapshot(); !maps.Equal(again, after) {
		t.Error("a second run of the migration changed stored values")
	}
}

// fraction counts the fractional-second digits of an RFC 3339 time.
func fraction(s string) int {
	_, frac, ok := strings.Cut(s, ".")
	if !ok {
		return 0
	}
	return len(strings.TrimSuffix(frac, "Z"))
}
