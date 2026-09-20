// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"fmt"
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
