// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"io"
	"log/slog"
	"sort"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
)

func TestSelectForPurge(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	mk := func(id string, ageDays int, size int64) purgeCandidate {
		return purgeCandidate{id: id, uri: "file:///" + id, size: size, finished: now.AddDate(0, 0, -ageDays)}
	}
	// Oldest first, as the query returns them.
	cands := []purgeCandidate{mk("old", 10, 60), mk("mid", 5, 60), mk("new", 1, 60)}

	t.Run("retention off purges nothing", func(t *testing.T) {
		if got := selectForPurge(cands, RetentionPolicy{}, now); len(got) != 0 {
			t.Fatalf("expected none, got %v", got)
		}
	})
	t.Run("age only", func(t *testing.T) {
		got := selectForPurge(cands, RetentionPolicy{MaxAgeDays: 7}, now)
		if got["old"] != "age" || len(got) != 1 {
			t.Fatalf("expected only old by age, got %v", got)
		}
	})
	t.Run("size backstop drops oldest survivors", func(t *testing.T) {
		// cap 100, three 60-byte survivors (180 total) -> drop the two oldest.
		got := selectForPurge(cands, RetentionPolicy{MaxTotalBytes: 100}, now)
		if got["old"] != "size" || got["mid"] != "size" || got["new"] != "" || len(got) != 2 {
			t.Fatalf("size backstop wrong: %v", got)
		}
	})
	t.Run("age then size on survivors", func(t *testing.T) {
		// age 7 removes "old" (by age); survivors mid+new = 120 > cap 100, so the
		// oldest survivor (mid) also goes, by size.
		got := selectForPurge(cands, RetentionPolicy{MaxAgeDays: 7, MaxTotalBytes: 100}, now)
		if got["old"] != "age" || got["mid"] != "size" || got["new"] != "" {
			t.Fatalf("combined policy wrong: %v", got)
		}
	})
}

// fakeStorage records deletions; Create/Open are unused by the sweep.
type fakeStorage struct{ deleted []string }

func (f *fakeStorage) Create(context.Context, string) (io.WriteCloser, string, error) {
	return nil, "", nil
}
func (f *fakeStorage) Open(context.Context, string) (io.ReadCloser, error) { return nil, nil }
func (f *fakeStorage) Delete(_ context.Context, uri string) error {
	f.deleted = append(f.deleted, uri)
	return nil
}

func newRetentionTestRepo(t *testing.T) *Repo {
	t.Helper()
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
		`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1','alice','Alice',?,?)`,
		`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t1','box','10.0.0.5','linux',?,?)`,
	} {
		if _, err := db.ExecContext(ctx, db.Rebind(q), now, now); err != nil {
			t.Fatal(err)
		}
	}
	return NewRepo(db)
}

func TestRetentionPolicyRoundTrip(t *testing.T) {
	ctx := context.Background()
	r := newRetentionTestRepo(t)

	got, err := r.GetRetentionPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxAgeDays != 0 || got.MaxTotalBytes != 0 || got.UpdatedAt != nil {
		t.Fatalf("unset policy should be zero, got %+v", got)
	}
	if err := r.SetRetentionPolicy(ctx, RetentionPolicy{MaxAgeDays: 30, MaxTotalBytes: 5 << 30}, "u1"); err != nil {
		t.Fatal(err)
	}
	got, err = r.GetRetentionPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxAgeDays != 30 || got.MaxTotalBytes != 5<<30 || got.UpdatedBy != "u1" || got.UpdatedAt == nil {
		t.Fatalf("policy not persisted: %+v", got)
	}
	// Upsert again to confirm the single row is replaced, not duplicated.
	if err := r.SetRetentionPolicy(ctx, RetentionPolicy{MaxAgeDays: 7}, "u1"); err != nil {
		t.Fatal(err)
	}
	got, _ = r.GetRetentionPolicy(ctx)
	if got.MaxAgeDays != 7 || got.MaxTotalBytes != 0 {
		t.Fatalf("upsert wrong: %+v", got)
	}
}

func TestSweepDeletesAndMarks(t *testing.T) {
	ctx := context.Background()
	r := newRetentionTestRepo(t)

	// Three finished recordings; backdate the oldest well past a 7-day policy.
	ids := make([]string, 3)
	ages := []int{20, 3, 1} // days old
	for i, age := range ages {
		s := &Session{UserID: "u1", TargetID: "t1", Protocol: "ssh", ClientIP: "10.0.0.1"}
		if err := r.Start(ctx, s); err != nil {
			t.Fatal(err)
		}
		rec := &Recording{SessionID: s.ID, Format: "asciicast", StorageURI: "file:///rec-" + s.ID + ".cast"}
		if err := r.CreateRecording(ctx, rec); err != nil {
			t.Fatal(err)
		}
		if err := r.FinishRecording(ctx, rec.ID, 100, "sha"); err != nil {
			t.Fatal(err)
		}
		finished := time.Now().UTC().AddDate(0, 0, -age)
		if _, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE recordings SET finished_at = ? WHERE id = ?`), store.TimeArg(finished), rec.ID); err != nil {
			t.Fatal(err)
		}
		ids[i] = rec.ID
	}

	if err := r.SetRetentionPolicy(ctx, RetentionPolicy{MaxAgeDays: 7}, "u1"); err != nil {
		t.Fatal(err)
	}
	fake := &fakeStorage{}
	sw := &RetentionSweeper{Repo: r, Storage: fake, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	n, err := sw.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(fake.deleted) != 1 {
		t.Fatalf("expected 1 purge, got n=%d deleted=%v", n, fake.deleted)
	}

	// The 20-day-old recording is purged (blob gone, row marked); the others stay.
	oldest, err := r.GetRecording(ctx, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if oldest.PurgedAt == nil {
		t.Fatal("oldest recording should be marked purged")
	}
	for _, id := range ids[1:] {
		rec, err := r.GetRecording(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if rec.PurgedAt != nil {
			t.Fatalf("recording %s should not be purged", id)
		}
	}

	// A second sweep is idempotent: the purged row is skipped, nothing new goes.
	n2, err := sw.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Fatalf("second sweep should purge nothing, got %d", n2)
	}
	sort.Strings(fake.deleted)
	if len(fake.deleted) != 1 {
		t.Fatalf("no further deletes expected, got %v", fake.deleted)
	}
}
