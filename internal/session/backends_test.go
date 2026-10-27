// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// TestRepoOnEachBackend proves the session repository on both engines: the
// retention policy's ON CONFLICT upsert, a session's start and end, the
// recording row's finish, and the open-only listing (review Q1, finding 2).
func TestRepoOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		stamp := store.TimeArg(time.Now())
		for _, q := range []string{
			`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1', 'alice', 'Alice', ?, ?)`,
			`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u2', 'bob', 'Bob', ?, ?)`,
			`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t1', 'box', '10.0.0.5', 'linux', ?, ?)`,
		} {
			if _, err := db.ExecContext(ctx, db.Rebind(q), stamp, stamp); err != nil {
				t.Fatal(err)
			}
		}
		r := NewRepo(db)
		if err := r.SetRetentionPolicy(ctx, RetentionPolicy{MaxAgeDays: 30, MaxTotalBytes: 1 << 30}, "u1"); err != nil {
			t.Fatal(err)
		}
		if err := r.SetRetentionPolicy(ctx, RetentionPolicy{MaxAgeDays: 7, MaxTotalBytes: 1 << 20}, "u2"); err != nil {
			t.Fatalf("the second set is an upsert: %v", err)
		}
		pol, err := r.GetRetentionPolicy(ctx)
		if err != nil || pol.MaxAgeDays != 7 || pol.MaxTotalBytes != 1<<20 || pol.UpdatedBy != "u2" || pol.UpdatedAt == nil {
			t.Fatalf("retention after two sets: %+v %v", pol, err)
		}

		s := &Session{UserID: "u1", TargetID: "t1", Protocol: "ssh", ClientIP: "10.0.0.1", UserAgent: "test"}
		if err := r.Start(ctx, s); err != nil {
			t.Fatal(err)
		}
		other := &Session{UserID: "u2", TargetID: "t1", Protocol: "rdp", ClientIP: "10.0.0.2"}
		if err := r.Start(ctx, other); err != nil {
			t.Fatal(err)
		}
		until := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Second)
		rec := &Recording{SessionID: s.ID, Format: "asciicast", StorageURI: "file:///tmp/" + s.ID + ".cast", RetentionUntil: &until}
		if err := r.CreateRecording(ctx, rec); err != nil {
			t.Fatal(err)
		}
		if err := r.FinishRecording(ctx, rec.ID, 1234, "abc"); err != nil {
			t.Fatal(err)
		}
		gotRec, err := r.GetRecording(ctx, rec.ID)
		if err != nil || gotRec.SizeBytes != 1234 || gotRec.SHA256 != "abc" || gotRec.FinishedAt == nil || gotRec.RetentionUntil == nil || !gotRec.RetentionUntil.Equal(until) {
			t.Fatalf("recording after finish: %+v %v", gotRec, err)
		}
		if err := r.End(ctx, s.ID, EndUserExit); err != nil {
			t.Fatal(err)
		}
		got, err := r.Get(ctx, s.ID)
		if err != nil || got.EndedAt == nil || got.EndReason != EndUserExit || got.RecordingID != rec.ID || got.EndedAt.Before(got.StartedAt) {
			t.Fatalf("ended session: %+v %v", got, err)
		}
		open, _, err := r.List(ctx, Filter{OpenOnly: true, Limit: 10})
		if err != nil || len(open) != 1 || open[0].ID != other.ID {
			t.Fatalf("open sessions: %+v %v", open, err)
		}
		all, _, err := r.List(ctx, Filter{Limit: 10})
		if err != nil || len(all) != 2 {
			t.Fatalf("all sessions: %d %v", len(all), err)
		}
		counts, err := r.Count(ctx, time.Now().Add(-time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		_ = counts
	})
}
