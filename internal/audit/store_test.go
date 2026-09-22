// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
)

func newTestLog(t *testing.T) (*Log, *store.DB) {
	t.Helper()
	db, err := store.Open(context.Background(), config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return NewLog(db), db
}

func TestRecordListVerify(t *testing.T) {
	ctx := context.Background()
	log, db := newTestLog(t)
	alice := Actor{UserID: "alice", IP: "10.0.0.1"}
	bob := Actor{UserID: "bob", IP: "10.0.0.2"}

	base := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	var stored []Event
	for i := 0; i < 7; i++ {
		actor, action := alice, "user.login"
		if i%2 == 1 {
			actor, action = bob, "target.create"
		}
		e := actor.Event(action, "target", fmt.Sprintf("t%d", i), Success, map[string]any{"n": i})
		e.Timestamp = base.Add(time.Duration(i) * time.Minute)
		got, err := log.Record(ctx, e)
		if err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		if got.ID != int64(i+1) || got.Hash == "" || got.PrevHash == "" {
			t.Fatalf("record %d: bad stored event %+v", i, got)
		}
		stored = append(stored, got)
	}
	if stored[0].PrevHash != GenesisHash {
		t.Fatal("first event must link to genesis")
	}
	for i := 1; i < len(stored); i++ {
		if stored[i].PrevHash != stored[i-1].Hash {
			t.Fatalf("event %d not linked to %d", i, i-1)
		}
	}

	// Newest first, full page.
	all, next, err := log.List(ctx, Filter{})
	if err != nil || len(all) != 7 || next != "" {
		t.Fatalf("list all: n=%d next=%q err=%v", len(all), next, err)
	}
	if all[0].ID != 7 || all[6].ID != 1 {
		t.Fatalf("list order wrong: %d..%d", all[0].ID, all[6].ID)
	}
	if !all[0].Timestamp.Equal(base.Add(6 * time.Minute)) {
		t.Fatalf("timestamp round trip: %v", all[0].Timestamp)
	}
	var d map[string]int
	if err := json.Unmarshal(all[0].Details, &d); err != nil || d["n"] != 6 {
		t.Fatalf("details round trip: %s %v", all[0].Details, err)
	}

	// Cursor pagination.
	p1, next, err := log.List(ctx, Filter{Limit: 3})
	if err != nil || len(p1) != 3 || next != "5" {
		t.Fatalf("page 1: n=%d next=%q err=%v", len(p1), next, err)
	}
	p2, next, err := log.List(ctx, Filter{Limit: 3, Cursor: next})
	if err != nil || len(p2) != 3 || next != "2" || p2[0].ID != 4 {
		t.Fatalf("page 2: n=%d next=%q err=%v", len(p2), next, err)
	}
	p3, next, err := log.List(ctx, Filter{Limit: 3, Cursor: next})
	if err != nil || len(p3) != 1 || next != "" || p3[0].ID != 1 {
		t.Fatalf("page 3: n=%d next=%q err=%v", len(p3), next, err)
	}
	if _, _, err := log.List(ctx, Filter{Cursor: "abc"}); err == nil {
		t.Fatal("expected invalid cursor error")
	}

	// Filters.
	byActor, _, err := log.List(ctx, Filter{ActorUserID: "bob"})
	if err != nil || len(byActor) != 3 {
		t.Fatalf("filter actor: n=%d err=%v", len(byActor), err)
	}
	byAction, _, err := log.List(ctx, Filter{Action: "user.login", ObjectType: "target"})
	if err != nil || len(byAction) != 4 {
		t.Fatalf("filter action: n=%d err=%v", len(byAction), err)
	}
	byObj, _, err := log.List(ctx, Filter{ObjectID: "t3"})
	if err != nil || len(byObj) != 1 || byObj[0].ID != 4 {
		t.Fatalf("filter object: n=%d err=%v", len(byObj), err)
	}
	byTime, _, err := log.List(ctx, Filter{From: base.Add(2 * time.Minute), To: base.Add(5 * time.Minute)})
	if err != nil || len(byTime) != 3 {
		t.Fatalf("filter time: n=%d err=%v", len(byTime), err)
	}

	// Verify intact.
	res, err := log.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Broken != nil || res.Checked != 7 || res.LastID != 7 || res.LastHash != stored[6].Hash {
		t.Fatalf("verify: %+v", res)
	}

	// Tamper with a row and verify again.
	if _, err := db.ExecContext(ctx, `UPDATE audit_events SET actor_user_id = 'mallory' WHERE id = 4`); err != nil {
		t.Fatal(err)
	}
	res, err = log.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Broken == nil || res.Broken.ID != 4 || res.Checked != 3 {
		t.Fatalf("expected break at id 4 after 3 checked, got %+v", res)
	}

	// Deleting a row is detected too.
	if _, err := db.ExecContext(ctx, `UPDATE audit_events SET actor_user_id = 'bob' WHERE id = 4`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM audit_events WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	res, err = log.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Broken == nil || res.Broken.ID != 3 {
		t.Fatalf("expected break at id 3 after deletion, got %+v", res)
	}
}

func TestRecordDefaults(t *testing.T) {
	ctx := context.Background()
	log, _ := newTestLog(t)
	before := time.Now().UTC().Add(-time.Second)
	got, err := log.Record(ctx, Event{Action: "system.start", Outcome: Success})
	if err != nil {
		t.Fatal(err)
	}
	if got.Timestamp.Before(before) || string(got.Details) != "{}" {
		t.Fatalf("defaults not applied: %+v", got)
	}
	if _, err := log.Record(ctx, Event{Action: "x"}); err == nil {
		t.Fatal("expected error for missing outcome")
	}
	if _, err := log.Record(ctx, Event{Outcome: Success}); err == nil {
		t.Fatal("expected error for missing action")
	}
	if _, err := log.Record(ctx, Event{Action: "x", Outcome: Failure, Details: json.RawMessage(`[1]`)}); err == nil {
		t.Fatal("expected error for non-object details")
	}
}

func TestRecordTimestampTruncatedForPortableHash(t *testing.T) {
	ctx := context.Background()
	log, _ := newTestLog(t)
	// A nanosecond-precision timestamp: PostgreSQL's TIMESTAMPTZ drops the
	// sub-microsecond part on read-back, which would break the chain hash.
	ts := time.Date(2026, 9, 21, 7, 10, 14, 798_760_321, time.UTC)
	got, err := log.Record(ctx, Event{Action: "user.login", Outcome: Success, Timestamp: ts})
	if err != nil {
		t.Fatal(err)
	}
	// The stored timestamp must carry no sub-microsecond digits, so the value a
	// TIMESTAMPTZ column returns is identical to the one that was hashed.
	if got.Timestamp.Nanosecond()%1000 != 0 {
		t.Fatalf("timestamp not truncated to microseconds: %d ns", got.Timestamp.Nanosecond())
	}
	// Simulate a microsecond-precision read-back and confirm the hash still holds.
	rb := got
	rb.Timestamp = got.Timestamp.Truncate(time.Microsecond)
	want, err := ComputeHash(rb)
	if err != nil {
		t.Fatal(err)
	}
	if want != got.Hash {
		t.Fatalf("hash not stable across microsecond truncation: got %s want %s", got.Hash, want)
	}
	res, err := log.Verify(ctx)
	if err != nil || res.Broken != nil {
		t.Fatalf("verify after truncation: %+v %v", res, err)
	}
}

func TestVerifyEmpty(t *testing.T) {
	log, _ := newTestLog(t)
	res, err := log.Verify(context.Background())
	if err != nil || res.Broken != nil || res.Checked != 0 || res.LastHash != GenesisHash {
		t.Fatalf("empty verify: %+v %v", res, err)
	}
}

func TestConcurrentRecordKeepsChainLinear(t *testing.T) {
	ctx := context.Background()
	log, _ := newTestLog(t)
	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := log.Record(ctx, Actor{UserID: fmt.Sprintf("u%d", i), IP: "127.0.0.1"}.Event("session.start", "session", fmt.Sprint(i), Success, nil))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	res, err := log.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Broken != nil || res.Checked != n {
		t.Fatalf("after concurrent writes: %+v", res)
	}
}

func TestVerifyBatching(t *testing.T) {
	ctx := context.Background()
	log, _ := newTestLog(t)
	total := verifyBatchSize + 5
	for i := 0; i < total; i++ {
		if _, err := log.Record(ctx, Event{Action: "tick", Outcome: Success}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := log.Verify(ctx)
	if err != nil || res.Broken != nil || res.Checked != int64(total) {
		t.Fatalf("batching verify: %+v %v", res, err)
	}
}

func TestListExcludeRoutineEvents(t *testing.T) {
	ctx := context.Background()
	log, _ := newTestLog(t)
	for _, e := range []Event{
		{Action: "audit.read", Outcome: Success},
		{Action: "session.connect", Outcome: Success},
		{Action: "session.connect", Outcome: Failure},
		{Action: "session.start", Outcome: Success},
	} {
		if _, err := log.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	got, _, err := log.List(ctx, Filter{Exclude: []string{"audit.read", "session.connect:success"}})
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range got {
		actions = append(actions, e.Action+":"+string(e.Outcome))
	}
	want := "session.start:success session.connect:failure"
	if strings.Join(actions, " ") != want {
		t.Fatalf("exclude: want %q, got %q", want, strings.Join(actions, " "))
	}
}

// TestReseal covers recovery from a chain broken by a hash-computation bug:
// the stored hash no longer matches the content and the original input is gone,
// so Verify can only pass again after a deliberate reseal.
func TestReseal(t *testing.T) {
	ctx := context.Background()
	log, db := newTestLog(t)

	actor := Actor{UserID: "alice", IP: "10.0.0.1"}
	for i := 0; i < 6; i++ {
		e := actor.Event("user.login", "user", fmt.Sprintf("u%d", i), Success, map[string]any{"n": i})
		if _, err := log.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if res, err := log.Verify(ctx); err != nil || res.Broken != nil {
		t.Fatalf("fresh chain must verify: err=%v broken=%+v", err, res.Broken)
	}

	// An intact chain is left completely alone.
	clean, err := log.Reseal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if clean.Rewritten != 0 {
		t.Fatalf("intact chain must not be rewritten, got %d", clean.Rewritten)
	}

	// Reproduce the shape of the timestamp bug: the stored content no longer
	// matches what the stored hash was computed over, and the original input is
	// unrecoverable. Recomputing therefore yields a *different* hash, which
	// changes the next row's prev_hash and cascades to the head.
	if _, err := db.ExecContext(ctx, db.Rebind(`UPDATE audit_events SET details = ? WHERE id = ?`),
		`{"n":99}`, 2); err != nil {
		t.Fatal(err)
	}
	broken, err := log.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if broken.Broken == nil {
		t.Fatal("corrupted chain must fail verification")
	}

	res, err := log.Reseal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rewritten == 0 {
		t.Fatal("reseal must rewrite the broken rows")
	}
	// Row 2's hash feeds every later hash, so the rewrite reaches the head.
	if res.FirstID != 2 || res.LastID != 6 {
		t.Fatalf("expected rewrite to span ids 2..6, got %d..%d", res.FirstID, res.LastID)
	}
	after, err := log.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Broken != nil {
		t.Fatalf("chain must verify after reseal: %+v", after.Broken)
	}
	if after.Checked != 6 {
		t.Fatalf("expected 6 events after reseal, got %d", after.Checked)
	}
}
