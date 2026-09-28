// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
)

// TestResolveNames covers every object type the audit page decorates,
// including the session and recording labels that join across tables.
func TestResolveNames(t *testing.T) {
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
	rec := &Recording{SessionID: s.ID, Format: "asciicast", StorageURI: "file:///dev/null"}
	if err := r.CreateRecording(ctx, rec); err != nil {
		t.Fatal(err)
	}

	cases := []struct{ kind, id, want string }{
		{"user", "u1", "alice"},
		{"target", "t1", "box"},
		{"access_session", s.ID, "alice → box (SSH)"},
		{"recording", rec.ID, "alice → box (SSH)"},
	}
	for _, c := range cases {
		got, err := r.ResolveNames(ctx, c.kind, []string{c.id, c.id, ""})
		if err != nil {
			t.Fatalf("%s: %v", c.kind, err)
		}
		if got[c.id] != c.want {
			t.Fatalf("%s %s: want %q, got %q", c.kind, c.id, c.want, got[c.id])
		}
	}
	if got, err := r.ResolveNames(ctx, "not_a_type", []string{"x"}); err != nil || len(got) != 0 {
		t.Fatalf("unknown type must resolve to nothing: %v %v", got, err)
	}
	if got, err := r.ResolveNames(ctx, "user", nil); err != nil || len(got) != 0 {
		t.Fatalf("no ids must resolve to nothing: %v %v", got, err)
	}

	id, err := r.UserIDByUsername(ctx, "ALICE")
	if err != nil || id != "u1" {
		t.Fatalf("username lookup is case-insensitive: %q %v", id, err)
	}
	id, err = r.UserIDByUsername(ctx, "nobody")
	if err != nil || id != "" {
		t.Fatalf("unknown username must be empty, got %q %v", id, err)
	}
}

// TestDetailIDs covers the read-time labelling of ids inside audit details:
// known keys are collected per kind, target_id is tried as a target and as an
// autoscaling instance, and malformed or non-string details are skipped.
func TestDetailIDs(t *testing.T) {
	items := []audit.Event{
		{Details: json.RawMessage(`{"target_id":"t1","policy_id":"p1","protocol":"ssh","n":3}`)},
		{Details: json.RawMessage(`not json`)},
		{Details: nil},
		{Details: json.RawMessage(`{"target_id":"i1","user_id":"","recording_id":"r1"}`)},
	}
	byKind, perEvent := detailIDs(items)
	if got := byKind["target"]; len(got) != 2 || got[0] != "t1" || got[1] != "i1" {
		t.Fatalf("target ids: %v", got)
	}
	if got := byKind["asg_instance"]; len(got) != 2 {
		t.Fatalf("target_id must also be tried as an instance: %v", got)
	}
	if got := byKind["access_policy"]; len(got) != 1 || got[0] != "p1" {
		t.Fatalf("policy ids: %v", got)
	}
	if _, ok := byKind["user"]; ok {
		t.Fatal("an empty id must not be collected")
	}
	if perEvent[0]["target_id"] != "t1" || perEvent[0]["policy_id"] != "p1" || perEvent[0]["protocol"] != "" {
		t.Fatalf("per-event pairs: %v", perEvent[0])
	}
	if perEvent[1] != nil || perEvent[2] != nil {
		t.Fatalf("malformed and empty details must yield nothing: %v %v", perEvent[1], perEvent[2])
	}
	if perEvent[3]["recording_id"] != "r1" {
		t.Fatalf("recording id: %v", perEvent[3])
	}
}
