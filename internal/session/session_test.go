// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"errors"
	"slices"
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
	if err != nil || got.RecordingID != rec.ID || got.EndedAt != nil || got.Username != "alice" || got.TargetName != "box" {
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

// TestSessionLabelsAndUsernameFilter covers what the admin and user tables
// read: a session on an autoscaling instance carries the group name and the
// cloud instance id, and List narrows by username the way it narrows by id.
func TestSessionLabelsAndUsernameFilter(t *testing.T) {
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
		`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u2', 'bob', 'Bob', ?, ?)`,
		`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t1', 'box', '10.0.0.5', 'linux', ?, ?)`,
		`INSERT INTO autoscaling_groups (id, name, provider, region, external_name, role_arn, external_id, os_family, created_at, updated_at) VALUES ('a1', 'fleet', 'aws', 'ap-south-1', 'fleet-asg', 'arn:aws:iam::1:role/r', 'ext', 'linux', ?, ?)`,
		`INSERT INTO asg_instances (id, asg_id, instance_id, lifecycle_state, first_seen_at, last_seen_at) VALUES ('i1', 'a1', 'i-0abc', 'InService', ?, ?)`,
	} {
		if _, err := db.ExecContext(ctx, db.Rebind(q), now, now); err != nil {
			t.Fatalf("%s: %v", q[:40], err)
		}
	}
	r := NewRepo(db)
	onBox := &Session{UserID: "u1", TargetID: "t1", Protocol: "ssh", ClientIP: "10.0.0.1"}
	onFleet := &Session{UserID: "u2", ASGID: "a1", ASGInstanceID: "i1", Protocol: "ssh", ClientIP: "10.0.0.1"}
	for _, s := range []*Session{onBox, onFleet} {
		if err := r.Start(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	got, err := r.Get(ctx, onFleet.ID)
	if err != nil || got.Username != "bob" || got.ASGName != "fleet" || got.InstanceID != "i-0abc" || got.TargetName != "" {
		t.Fatalf("autoscaling session labels: %+v %v", got, err)
	}
	got, _ = r.Get(ctx, onBox.ID)
	if got.TargetName != "box" || got.ASGName != "" || got.InstanceID != "" {
		t.Fatalf("static target session labels: %+v", got)
	}
	cases := []struct {
		username string
		want     int
	}{
		{"alice", 1},
		{" Alice ", 1}, // trimmed and lower-cased, as usernames are stored
		{"bob", 1},
		{"carol", 0},
		{"", 2}, // no filter
	}
	for _, c := range cases {
		list, _, err := r.List(ctx, Filter{Username: c.username})
		if err != nil || len(list) != c.want {
			t.Fatalf("Filter{Username: %q}: got %d %v, want %d", c.username, len(list), err, c.want)
		}
	}
}

// TestListOrdersInsideASecond: sessions are listed newest first and paged by
// start time (M28). On SQLite started_at is text, so the order inside a
// shared second, and the cursor, must compare as times. A cursor is read as
// a time and written back in the stored form, so one an older build handed
// out (trimmed) or one with an offset pages the same way.
func TestListOrdersInsideASecond(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, db.Rebind(q), args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1', 'alice', 'Alice', ?, ?)`, store.TimeArg(base), store.TimeArg(base))
	exec(`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t1', 'box', '10.0.0.5', 'linux', ?, ?)`, store.TimeArg(base), store.TimeArg(base))
	for id, at := range map[string]time.Duration{"s1": 0, "s2": 500 * time.Millisecond, "s3": time.Second} {
		exec(`INSERT INTO access_sessions (id, user_id, target_id, protocol, client_ip, started_at) VALUES (?, 'u1', 't1', 'ssh', '10.0.0.1', ?)`, id, store.TimeArg(base.Add(at)))
	}
	r := NewRepo(db)
	ids := func(f Filter) ([]string, string) {
		t.Helper()
		list, next, err := r.List(ctx, f)
		if err != nil {
			t.Fatalf("list %+v: %v", f, err)
		}
		var out []string
		for _, s := range list {
			out = append(out, s.ID)
		}
		return out, next
	}
	if got, _ := ids(Filter{}); !slices.Equal(got, []string{"s3", "s2", "s1"}) {
		t.Errorf("newest first: %v", got)
	}
	// One at a time, by the cursor each page returns.
	var paged []string
	cursor := ""
	for range 4 {
		page, next := ids(Filter{Limit: 1, Cursor: cursor})
		paged = append(paged, page...)
		if next == "" {
			break
		}
		cursor = next
	}
	if !slices.Equal(paged, []string{"s3", "s2", "s1"}) {
		t.Errorf("paged one at a time: %v", paged)
	}
	for _, c := range []struct {
		cursor string
		want   []string
	}{
		{"2026-10-11T10:00:00.5Z", []string{"s1"}},      // trimmed, as builds before 0030 wrote it
		{"2026-10-11T10:00:01Z", []string{"s2", "s1"}},  // whole seconds
		{"2026-10-11T15:30:00.5+05:30", []string{"s1"}}, // the same instant with an offset
		{"2026-10-11T10:00:00.500000Z", []string{"s1"}}, // the stored form
	} {
		if got, _ := ids(Filter{Cursor: c.cursor}); !slices.Equal(got, c.want) {
			t.Errorf("before cursor %q: %v, want %v", c.cursor, got, c.want)
		}
	}
	if _, _, err := r.List(ctx, Filter{Cursor: "yesterday"}); !errors.Is(err, ErrBadCursor) {
		t.Errorf("a cursor that is not a time: %v, want ErrBadCursor", err)
	}
}
