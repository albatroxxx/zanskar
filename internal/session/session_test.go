// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
)

func TestSessionsAndRecordings(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	now := store.TimeArg(time.Now())
	for _, q := range []string{
		`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1', 'alice', 'Alice', ?, ?)`,
		`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t1', 'box', '10.0.0.5', 'linux', ?, ?)`,
	} {
		if _, err := db.ExecContext(ctx, db.Rebind(q), now, now); err != nil {
			t.Fatal(err)
		}
	}
	r := NewRepo(db)
	s := &Session{UserID: "u1", TargetID: "t1", Protocol: "ssh", ClientIP: "10.0.0.1"}
	if err := r.Start(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, &Session{UserID: "u1", Protocol: "ssh", ClientIP: "x"}); err == nil {
		t.Fatal("session without target or instance must be rejected by CHECK")
	}
	rec := &Recording{SessionID: s.ID, Format: "asciicast", StorageURI: "file:///tmp/x.cast"}
	if err := r.CreateRecording(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := r.FinishRecording(ctx, rec.ID, 1234, "abc"); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(ctx, s.ID)
	if err != nil || got.RecordingID != rec.ID || got.EndedAt != nil {
		t.Fatalf("get: %+v %v", got, err)
	}
	open, _, _ := r.List(ctx, Filter{UserID: "u1", OpenOnly: true})
	if len(open) != 1 {
		t.Fatalf("expected 1 open session, got %d", len(open))
	}
	if err := r.End(ctx, s.ID, EndUserExit); err != nil {
		t.Fatal(err)
	}
	if err := r.End(ctx, s.ID, EndError); err != nil {
		t.Fatal(err)
	}
	got, _ = r.Get(ctx, s.ID)
	if got.EndedAt == nil || got.EndReason != EndUserExit {
		t.Fatalf("end reason must not be overwritten: %+v", got)
	}
	gr, err := r.GetRecording(ctx, rec.ID)
	if err != nil || gr.SizeBytes != 1234 || gr.SHA256 != "abc" || gr.FinishedAt == nil {
		t.Fatalf("recording: %+v %v", gr, err)
	}
	if err := r.RecordView(ctx, rec.ID, "u1", "10.0.0.9"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal("expected not found")
	}
	// Pagination newest-first.
	for i := 0; i < 3; i++ {
		if err := r.Start(ctx, &Session{UserID: "u1", TargetID: "t1", Protocol: "ssh", ClientIP: "x"}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	page, next, err := r.List(ctx, Filter{UserID: "u1", Limit: 2})
	if err != nil || len(page) != 2 || next == "" {
		t.Fatalf("page1: %d next=%q err=%v", len(page), next, err)
	}
	page2, next2, _ := r.List(ctx, Filter{UserID: "u1", Limit: 2, Cursor: next})
	if len(page2) != 2 || next2 != "" || page2[0].ID == page[0].ID {
		t.Fatalf("page2: %d next=%q", len(page2), next2)
	}
}
