// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
)

// testKey signs anchors in these tests; otherKey stands for any other key,
// such as one derived from another gateway's master key.
var (
	testKey  = bytes.Repeat([]byte{9}, 32)
	otherKey = bytes.Repeat([]byte{8}, 32)
)

// forEachBackend runs fn on SQLite in memory and, when
// ZANSKAR_TEST_POSTGRES_DSN is set, on PostgreSQL in a schema of its own.
func forEachBackend(t *testing.T, fn func(t *testing.T, log *Log, db *store.DB)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) {
		log, db := newTestLog(t)
		fn(t, log, db)
	})
	dsn := os.Getenv("ZANSKAR_TEST_POSTGRES_DSN")
	if dsn == "" {
		return
	}
	t.Run("postgres", func(t *testing.T) {
		db := isolatedPostgres(t, dsn)
		if _, err := store.Migrate(context.Background(), db); err != nil {
			t.Fatal(err)
		}
		fn(t, NewLog(db), db)
	})
}

// isolatedPostgres opens dsn on a fresh schema dropped at cleanup, so these
// tests share no rows, and no sequence, with anything else.
func isolatedPostgres(t *testing.T, dsn string) *store.DB {
	t.Helper()
	ctx := context.Background()
	admin, err := store.Open(ctx, config.DriverPostgres, dsn)
	if err != nil {
		t.Fatal(err)
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	schema := "audit_test_" + hex.EncodeToString(b[:])
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := store.Open(ctx, config.DriverPostgres, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_, _ = admin.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		_ = admin.Close()
	})
	return db
}

// record appends n events and returns them as stored.
func record(t *testing.T, log *Log, n int) []Event {
	t.Helper()
	out := make([]Event, 0, n)
	for i := range n {
		ev, err := log.Record(context.Background(), Actor{UserID: "alice", IP: "10.0.0.1"}.Event("user.login", "user", fmt.Sprint(i), Success, map[string]any{"n": i}))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

func anchorNow(t *testing.T, log *Log) Anchor {
	t.Helper()
	a, err := log.Anchor(context.Background(), testKey)
	if err != nil || a.ID == 0 {
		t.Fatalf("anchor: %+v %v", a, err)
	}
	return a
}

func verify(t *testing.T, log *Log, kept ...Anchor) VerifyResult {
	t.Helper()
	res, err := log.Verify(context.Background(), testKey, kept...)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func exec(t *testing.T, db *store.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), db.Rebind(q), args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// hasProblem reports whether some problem contains every fragment.
func hasProblem(list []string, fragments ...string) bool {
	for _, p := range list {
		all := true
		for _, f := range fragments {
			all = all && strings.Contains(p, f)
		}
		if all {
			return true
		}
	}
	return false
}

// rehash relinks and rehashes the whole chain with raw SQL, as someone with
// write access to the database (and this source code) would after editing
// an event, so the chain itself links again.
func rehash(t *testing.T, log *Log, db *store.DB) {
	t.Helper()
	events, err := log.ListAfter(context.Background(), 0, maxListLimit)
	if err != nil {
		t.Fatal(err)
	}
	prev := GenesisHash
	for _, e := range events {
		e.PrevHash = prev
		h, err := ComputeHash(e)
		if err != nil {
			t.Fatal(err)
		}
		exec(t, db, `UPDATE audit_events SET prev_hash = ?, hash = ? WHERE id = ?`, prev, h, e.ID)
		prev = h
	}
}

// TestAnchorWrittenAndIdempotent: an empty log has nothing to anchor; an
// anchor names the newest event with a MAC under the key, survives the round
// trip through the database (PostgreSQL keeps microseconds), and is written
// again only once there is a newer event.
func TestAnchorWrittenAndIdempotent(t *testing.T) {
	forEachBackend(t, func(t *testing.T, log *Log, _ *store.DB) {
		ctx := context.Background()
		if _, err := log.Anchor(ctx, nil); !errors.Is(err, ErrNoAnchorKey) {
			t.Fatalf("anchor without a key: %v", err)
		}
		if a, err := log.Anchor(ctx, testKey); err != nil || a != (Anchor{}) {
			t.Fatalf("anchor of an empty log: %+v %v", a, err)
		}

		evs := record(t, log, 3)
		before := time.Now().UTC().Add(-time.Minute)
		first := anchorNow(t, log)
		if first.EventID != evs[2].ID || first.Hash != evs[2].Hash || !first.Signed(testKey) || first.Signed(otherKey) {
			t.Fatalf("anchor %+v does not sign the newest event %d %s under the key", first, evs[2].ID, evs[2].Hash)
		}
		if first.CreatedAt.Before(before) || first.CreatedAt.Nanosecond()%1000 != 0 {
			t.Fatalf("anchor time %v: want now, in whole microseconds", first.CreatedAt)
		}

		again := anchorNow(t, log)
		stored, err := log.Anchors(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if again.ID != first.ID || len(stored) != 1 || !stored[0].Signed(testKey) || !stored[0].CreatedAt.Equal(first.CreatedAt) {
			t.Fatalf("a second anchor with no new event: %+v, stored %+v", again, stored)
		}

		newer := record(t, log, 1)[0]
		second := anchorNow(t, log)
		if second.ID == first.ID || second.EventID != newer.ID {
			t.Fatalf("anchor after a new event: %+v", second)
		}
	})
}

// TestVerifyWithAnchors: an intact log with anchors verifies, reports the
// anchor over the newest event and has nothing to warn about; a missing key
// is refused rather than the signatures skipped.
func TestVerifyWithAnchors(t *testing.T) {
	forEachBackend(t, func(t *testing.T, log *Log, _ *store.DB) {
		record(t, log, 4)
		anchorNow(t, log)
		evs := record(t, log, 2)
		newest := anchorNow(t, log)

		res := verify(t, log)
		if !res.Intact() || res.Checked != 6 || res.Anchors != 2 || len(res.Problems) != 0 || len(res.Warnings) != 0 {
			t.Fatalf("verify an intact anchored log: %+v", res)
		}
		if res.LastAnchor == nil || res.LastAnchor.ID != newest.ID || res.LastAnchor.EventID != evs[1].ID {
			t.Fatalf("last anchor %+v, want %+v", res.LastAnchor, newest)
		}
		if _, err := log.Verify(context.Background(), nil); !errors.Is(err, ErrNoAnchorKey) {
			t.Fatalf("verify without a key: %v", err)
		}
	})
}

// TestVerifyDetectsTruncatedTail: deleting the newest three events, as a
// database-only attacker would, leaves a chain that links; the anchor over
// the old head and the id sequence both say what happened. (Before anchors,
// Verify called this log intact.)
func TestVerifyDetectsTruncatedTail(t *testing.T) {
	forEachBackend(t, func(t *testing.T, log *Log, db *store.DB) {
		evs := record(t, log, 6)
		a := anchorNow(t, log)
		exec(t, db, `DELETE FROM audit_events WHERE id > ?`, evs[2].ID)

		res := verify(t, log)
		if res.Broken != nil || res.Checked != 3 {
			t.Fatalf("the remaining chain still links: %+v", res)
		}
		if res.Intact() || res.LastAnchor != nil {
			t.Fatalf("a truncated log must not verify: %+v", res)
		}
		want := fmt.Sprintf("the log ends at event %d, but anchor %d covers event %d: the newest events were deleted", evs[2].ID, a.ID, evs[5].ID)
		if len(res.Problems) == 0 || res.Problems[0] != want {
			t.Fatalf("problems %q, want first %q", res.Problems, want)
		}
		seq := fmt.Sprintf("the id sequence is ahead of the newest event (%d vs %d)", evs[5].ID, evs[2].ID)
		if db.Driver == config.DriverPostgres {
			if !hasProblem(res.Warnings, seq, "or an insert failed") {
				t.Fatalf("warnings %q, want the sequence warning", res.Warnings)
			}
		} else if !hasProblem(res.Problems, seq, "events were deleted from the end of the log") {
			t.Fatalf("problems %q, want the sequence problem", res.Problems)
		}
	})
}

// TestSequenceCatchesADeletedTailBeforeAnyAnchor: with no anchor yet, the id
// sequence still remembers the deleted events. On SQLite that is proof; on
// PostgreSQL, where a failed insert also uses up an id, it is a warning.
func TestSequenceCatchesADeletedTailBeforeAnyAnchor(t *testing.T) {
	forEachBackend(t, func(t *testing.T, log *Log, db *store.DB) {
		evs := record(t, log, 5)
		exec(t, db, `DELETE FROM audit_events WHERE id > ?`, evs[2].ID)
		res := verify(t, log)
		seq := fmt.Sprintf("the id sequence is ahead of the newest event (%d vs %d)", evs[4].ID, evs[2].ID)
		if db.Driver == config.DriverPostgres {
			if !res.Intact() || !hasProblem(res.Warnings, seq) {
				t.Fatalf("postgres: want an intact result with the sequence warning, got %+v", res)
			}
			return
		}
		if res.Intact() || res.Broken != nil || len(res.Problems) != 1 || !hasProblem(res.Problems, seq) {
			t.Fatalf("sqlite: want the sequence problem alone, got %+v", res)
		}
	})
}

// TestVerifyDetectsEditedAnchoredEvent: editing an event and recomputing
// every later hash makes the chain link again, but an anchor over a rewritten
// event no longer matches; overwriting an anchored hash breaks both.
func TestVerifyDetectsEditedAnchoredEvent(t *testing.T) {
	forEachBackend(t, func(t *testing.T, log *Log, db *store.DB) {
		evs := record(t, log, 4)
		a := anchorNow(t, log)
		record(t, log, 2)

		exec(t, db, `UPDATE audit_events SET actor_ip = ? WHERE id = ?`, "198.51.100.7", evs[1].ID)
		rehash(t, log, db)
		res := verify(t, log)
		want := fmt.Sprintf("anchor %d: event %d has changed since it was anchored — the log was edited", a.ID, evs[3].ID)
		if res.Broken != nil || res.Intact() || len(res.Problems) != 1 || res.Problems[0] != want {
			t.Fatalf("a consistent rewrite: %+v, want only %q", res, want)
		}

		exec(t, db, `UPDATE audit_events SET hash = ? WHERE id = ?`, strings.Repeat("ab", 32), evs[3].ID)
		res = verify(t, log)
		if res.Broken == nil || res.Broken.ID != evs[3].ID || !hasProblem(res.Problems, fmt.Sprintf("anchor %d: event %d has changed", a.ID, evs[3].ID)) {
			t.Fatalf("an overwritten anchored hash: %+v", res)
		}
	})
}

// TestVerifyRejectsForgedAnchors: an anchor row the gateway did not sign, or
// a genuine one whose hash was changed to match a rewritten chain, is
// reported as not written by this gateway; past maxAnchorReports the rest
// are counted.
func TestVerifyRejectsForgedAnchors(t *testing.T) {
	forEachBackend(t, func(t *testing.T, log *Log, db *store.DB) {
		evs := record(t, log, 3)
		genuine := anchorNow(t, log)
		forged := Anchor{EventID: evs[1].ID, Hash: evs[1].Hash, CreatedAt: time.Now().UTC().Truncate(time.Microsecond)}
		forged.MAC = forged.mac(otherKey)
		exec(t, db, `INSERT INTO audit_anchors (event_id, hash, created_at, mac) VALUES (?, ?, ?, ?)`, forged.EventID, forged.Hash, store.TimeArg(forged.CreatedAt), forged.MAC)

		res := verify(t, log)
		stored, _ := log.Anchors(context.Background())
		want := fmt.Sprintf("anchor %d was not written by this gateway: its signature does not match", stored[1].ID)
		if res.Intact() || len(res.Problems) != 1 || res.Problems[0] != want || res.LastAnchor == nil || res.LastAnchor.ID != genuine.ID {
			t.Fatalf("a forged anchor: %+v, want only %q", res, want)
		}

		exec(t, db, `UPDATE audit_anchors SET hash = ? WHERE id = ?`, evs[0].Hash, genuine.ID)
		res = verify(t, log)
		if !hasProblem(res.Problems, fmt.Sprintf("anchor %d was not written by this gateway", genuine.ID)) || res.LastAnchor != nil {
			t.Fatalf("an altered anchor: %+v", res)
		}

		for range maxAnchorReports + 3 {
			exec(t, db, `INSERT INTO audit_anchors (event_id, hash, created_at, mac) VALUES (?, ?, ?, ?)`, evs[0].ID, evs[0].Hash, store.TimeArg(time.Now()), strings.Repeat("0", 64))
		}
		res = verify(t, log)
		if len(res.Problems) != maxAnchorReports+1 || res.Problems[maxAnchorReports] != "and 5 more anchor problem(s)" {
			t.Fatalf("problems past the cap: %d %q", len(res.Problems), res.Problems[len(res.Problems)-1])
		}
	})
}

// TestVerifyKeptAnchor: someone with full database access can delete the
// newest events and every stored anchor and rewind the id sequence, and the
// stored checks then pass. An anchor kept outside the database still shows
// the truncation; one altered in transit is refused; a kept anchor over an
// event still in the log matches.
func TestVerifyKeptAnchor(t *testing.T) {
	forEachBackend(t, func(t *testing.T, log *Log, db *store.DB) {
		evs := record(t, log, 6)
		kept, err := ParseAnchor(anchorNow(t, log).Line())
		if err != nil {
			t.Fatal(err)
		}
		if res := verify(t, log, kept); !res.Intact() || res.Anchors != 2 || res.LastAnchor == nil || res.LastAnchor.EventID != evs[5].ID {
			t.Fatalf("a kept anchor over the head: %+v", res)
		}

		exec(t, db, `DELETE FROM audit_events WHERE id > ?`, evs[2].ID)
		exec(t, db, `DELETE FROM audit_anchors`)
		if db.Driver == config.DriverPostgres {
			exec(t, db, `SELECT setval('audit_events_id_seq', ?)`, evs[2].ID)
		} else {
			exec(t, db, `UPDATE sqlite_sequence SET seq = ? WHERE name = 'audit_events'`, evs[2].ID)
		}
		if res := verify(t, log); !res.Intact() || len(res.Warnings) != 0 {
			t.Fatalf("with every trace removed from the database the stored checks pass: %+v", res)
		}

		res := verify(t, log, kept)
		want := fmt.Sprintf("the log ends at event %d, but the supplied anchor covers event %d: the newest events were deleted", evs[2].ID, evs[5].ID)
		if res.Intact() || len(res.Problems) != 1 || res.Problems[0] != want {
			t.Fatalf("a kept anchor after truncation: %+v, want %q", res, want)
		}

		altered := kept
		altered.EventID = evs[1].ID
		altered.Hash = evs[1].Hash
		res = verify(t, log, altered)
		if !hasProblem(res.Problems, fmt.Sprintf("the supplied anchor for event %d was not written by this gateway", evs[1].ID)) {
			t.Fatalf("an altered kept anchor: %+v", res)
		}
	})
}

// TestResignAnchors: a master-key rotation re-signs every genuine anchor
// under the new key and leaves a forged one as it was; running it again
// changes nothing.
func TestResignAnchors(t *testing.T) {
	forEachBackend(t, func(t *testing.T, log *Log, db *store.DB) {
		ctx := context.Background()
		evs := record(t, log, 2)
		anchorNow(t, log)
		exec(t, db, `INSERT INTO audit_anchors (event_id, hash, created_at, mac) VALUES (?, ?, ?, ?)`, evs[0].ID, evs[0].Hash, store.TimeArg(time.Now()), strings.Repeat("0", 64))

		if _, _, err := log.ResignAnchors(ctx, testKey, nil); !errors.Is(err, ErrNoAnchorKey) {
			t.Fatalf("re-sign without a key: %v", err)
		}
		resigned, skipped, err := log.ResignAnchors(ctx, testKey, otherKey)
		if err != nil || resigned != 1 || skipped != 1 {
			t.Fatalf("re-sign: %d %d %v", resigned, skipped, err)
		}
		res, err := log.Verify(ctx, otherKey)
		if err != nil || len(res.Problems) != 1 || !strings.Contains(res.Problems[0], "was not written by this gateway") || res.LastAnchor == nil {
			t.Fatalf("verify under the new key: %+v %v", res, err)
		}
		if res := verify(t, log); len(res.Problems) != 2 {
			t.Fatalf("under the old key both anchors are now foreign: %+v", res)
		}
		if resigned, skipped, err := log.ResignAnchors(ctx, testKey, otherKey); err != nil || resigned != 0 || skipped != 1 {
			t.Fatalf("a second re-sign: %d %d %v", resigned, skipped, err)
		}
	})
}

// TestAnchorRefusesAfterRotation: a gateway that kept running through a
// master-key rotation holds the old key. Once the stored anchors are
// re-signed under the new one, it must not write an anchor of its own: that
// anchor would fail every later verification, with no key left to re-sign
// it. The new key anchors as usual.
func TestAnchorRefusesAfterRotation(t *testing.T) {
	forEachBackend(t, func(t *testing.T, log *Log, _ *store.DB) {
		ctx := context.Background()
		record(t, log, 2)
		anchorNow(t, log)
		if _, _, err := log.ResignAnchors(ctx, testKey, otherKey); err != nil {
			t.Fatal(err)
		}
		record(t, log, 1)
		if _, err := log.Anchor(ctx, testKey); !errors.Is(err, ErrAnchorKeyMismatch) {
			t.Fatalf("anchor under the old key after a rotation: %v", err)
		}
		a, err := log.Anchor(ctx, otherKey)
		if err != nil || !a.Signed(otherKey) {
			t.Fatalf("anchor under the new key: %+v %v", a, err)
		}
		if res, err := log.Verify(ctx, otherKey); err != nil || !res.Intact() {
			t.Fatalf("verify under the new key: %+v %v", res, err)
		}
	})
}

// TestResealRemovesStaleAnchors: a reseal rewrites every hash from the first
// break, so the anchors over rewritten events go with it, in the same
// transaction; an anchor over an event that is missing stays, so the gap is
// still reported.
func TestResealRemovesStaleAnchors(t *testing.T) {
	forEachBackend(t, func(t *testing.T, log *Log, db *store.DB) {
		evs := record(t, log, 5)
		overMissing := anchorNow(t, log) // event 5
		evs = append(evs, record(t, log, 1)...)
		anchorNow(t, log) // event 6, which the reseal rewrites
		evs = append(evs, record(t, log, 1)...)
		exec(t, db, `DELETE FROM audit_events WHERE id IN (?, ?)`, evs[2].ID, evs[4].ID)

		before := verify(t, log)
		if before.Broken == nil || before.Broken.ID != evs[3].ID {
			t.Fatalf("the deletions break the chain at event %d: %+v", evs[3].ID, before)
		}
		res, err := log.Reseal(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if res.FirstID != evs[3].ID || res.AnchorsRemoved != 1 {
			t.Fatalf("reseal: %+v, want a rewrite from event %d and one anchor removed", res, evs[3].ID)
		}
		after := verify(t, log)
		want := fmt.Sprintf("anchor %d: event %d is missing — the log was truncated or edited", overMissing.ID, evs[4].ID)
		if after.Broken != nil || len(after.Problems) != 1 || after.Problems[0] != want {
			t.Fatalf("after the reseal: %+v, want only %q", after, want)
		}
	})
}

// TestParseAnchor: the printed line reads back, with or without its leading
// word and in any case; anything else is refused with a reason.
func TestParseAnchor(t *testing.T) {
	a := Anchor{EventID: 42, Hash: strings.Repeat("ab", 32), CreatedAt: time.Date(2026, 10, 11, 9, 30, 0, 120_000, time.UTC)}
	a.MAC = a.mac(testKey)
	for _, line := range []string{a.Line(), strings.TrimPrefix(a.Line(), "anchor "), "  " + strings.ToUpper(strings.TrimPrefix(a.Line(), "anchor ")) + "\n"} {
		got, err := ParseAnchor(line)
		if err != nil || got.EventID != a.EventID || got.Hash != a.Hash || !got.CreatedAt.Equal(a.CreatedAt) || got.MAC != a.MAC || !got.Signed(testKey) {
			t.Fatalf("parse %q: %+v %v", line, got, err)
		}
	}
	// The same instant written with another offset signs alike.
	if got, err := ParseAnchor(fmt.Sprintf("42 %s 2026-10-11T15:00:00.00012+05:30 %s", a.Hash, a.MAC)); err != nil || !got.Signed(testKey) {
		t.Fatalf("an equal instant in another zone: %+v %v", got, err)
	}
	for _, bad := range []string{
		"",
		"anchor 42 " + a.Hash,
		"anchor x " + a.Hash + " 2026-10-11T09:30:00Z " + a.MAC,
		"anchor -1 " + a.Hash + " 2026-10-11T09:30:00Z " + a.MAC,
		"anchor 42 " + a.Hash + " yesterday " + a.MAC,
		"anchor 42 abc 2026-10-11T09:30:00Z " + a.MAC,
		"anchor 42 " + a.Hash + " 2026-10-11T09:30:00Z " + strings.Repeat("zz", 32),
	} {
		if _, err := ParseAnchor(bad); err == nil {
			t.Errorf("parse %q: want a refusal", bad)
		}
	}
}

// syncBuffer is a log destination safe to read while the anchorer writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestAnchorerLogsEachNewAnchorOnce: the gateway's loop anchors at start and
// logs the anchor with every field a verifier needs, in full precision; a tick
// with no new event logs nothing more.
func TestAnchorerLogsEachNewAnchorOnce(t *testing.T) {
	log, _ := newTestLog(t)
	record(t, log, 2)
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	a := &Anchorer{Log: log, Key: testKey, Logger: slog.New(slog.NewJSONHandler(&out, nil)), Interval: 5 * time.Millisecond}
	go func() { a.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), `"audit anchor"`) {
		if time.Now().After(deadline) {
			t.Fatal("no anchor logged")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // several ticks, none with a new event
	cancel()
	<-done

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want one anchor line, got:\n%s", out.String())
	}
	var rec struct {
		Msg       string `json:"msg"`
		EventID   int64  `json:"event_id"`
		Hash      string `json:"hash"`
		CreatedAt string `json:"created_at"`
		MAC       string `json:"mac"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	kept, err := ParseAnchor(fmt.Sprintf("%d %s %s %s", rec.EventID, rec.Hash, rec.CreatedAt, rec.MAC))
	if err != nil || rec.Msg != "audit anchor" || !kept.Signed(testKey) {
		t.Fatalf("the logged anchor must verify: %+v %v", rec, err)
	}
	if res := verify(t, log, kept); !res.Intact() || res.LastAnchor == nil {
		t.Fatalf("verify against the logged anchor: %+v", res)
	}
}

// TestAnchorsSurviveTheFixedWidthRewrite: migration 0030 rewrites stored
// times into one fixed width on SQLite (M28), audit_anchors.created_at
// included. An anchor's signature covers its time as parsed, so an anchor
// stored in the old trimmed form must still verify after the rewrite.
func TestAnchorsSurviveTheFixedWidthRewrite(t *testing.T) {
	ctx := context.Background()
	log, db := newTestLog(t)
	ev, err := log.Record(ctx, Actor{IP: "10.0.0.1"}.Event(UserLogin, "user", "u1", Success, nil))
	if err != nil {
		t.Fatal(err)
	}
	// As a build before 0030 stored it: trailing zeros trimmed.
	a := Anchor{EventID: ev.ID, Hash: ev.Hash, CreatedAt: time.Date(2026, 10, 5, 10, 0, 0, 500_000_000, time.UTC)}
	a.MAC = a.mac(testKey)
	if _, err := db.ExecContext(ctx, `INSERT INTO audit_anchors (event_id, hash, created_at, mac) VALUES (?, ?, ?, ?)`,
		a.EventID, a.Hash, "2026-10-05T10:00:00.5Z", a.MAC); err != nil {
		t.Fatal(err)
	}
	check := func(when string) {
		t.Helper()
		res, err := log.Verify(ctx, testKey)
		if err != nil || res.Broken != nil || len(res.Problems) > 0 || res.LastAnchor == nil {
			t.Fatalf("%s: %+v %v", when, res, err)
		}
	}
	check("before the rewrite")

	if _, err := db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = '0030_fixed_width_timestamps'`); err != nil {
		t.Fatal(err)
	}
	if ran, err := store.Migrate(ctx, db); err != nil || len(ran) != 1 {
		t.Fatalf("rerun 0030: %v %v", ran, err)
	}
	var stored string
	if err := db.QueryRowContext(ctx, `SELECT created_at FROM audit_anchors`).Scan(&stored); err != nil || stored != "2026-10-05T10:00:00.500000Z" {
		t.Fatalf("the anchor's time was not rewritten: %q %v", stored, err)
	}
	check("after the rewrite")
}
