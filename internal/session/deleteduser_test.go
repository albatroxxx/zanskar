// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

const (
	lastWithUserRestrict = "0053_forget_security_contact"
	usersDeletable       = "0054_users_deletable"
)

func seedPerson(t *testing.T, db *store.DB) {
	t.Helper()
	now := store.TimeArg(time.Now())
	for _, q := range []string{
		`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1', 'alice', 'Alice Doe', ?, ?)`,
		`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t1', 'box', '10.0.0.5', 'linux', ?, ?)`,
	} {
		if _, err := db.ExecContext(context.Background(), db.Rebind(q), now, now); err != nil {
			t.Fatal(err)
		}
	}
}

// On each backend, an account is deleted whatever it did, and its history
// stays whole: the session and the recording view keep the id, the username
// and the display name as they were; every reader still names the person and
// says the account is gone; a new account with the same username is a
// different person to the old history (ADR 0046).
func TestDeletingAnAccountKeepsItsHistory(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		seedPerson(t, db)
		r := NewRepo(db)
		s := &Session{UserID: "u1", TargetID: "t1", Protocol: "ssh", ClientIP: "10.0.0.1"}
		if err := r.Start(ctx, s); err != nil {
			t.Fatal(err)
		}
		rec := &Recording{SessionID: s.ID, Format: "asciicast", StorageURI: "file:///tmp/x.cast"}
		if err := r.CreateRecording(ctx, rec); err != nil {
			t.Fatal(err)
		}
		if err := r.RecordView(ctx, rec.ID, "u1", "10.0.0.9"); err != nil {
			t.Fatal(err)
		}
		if got, _ := r.Get(ctx, s.ID); got.UserDeleted || got.Username != "alice" {
			t.Fatalf("a live account is not marked deleted: %+v", got)
		}

		if _, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = 'u1'`); err != nil {
			t.Fatalf("an account with a session and a recording view must delete: %v", err)
		}

		got, err := r.Get(ctx, s.ID)
		if err != nil || got.UserID != "u1" || got.Username != "alice" || !got.UserDeleted {
			t.Fatalf("the session after the delete: %+v %v", got, err)
		}
		list, _, err := r.List(ctx, Filter{UserID: "u1"})
		if err != nil || len(list) != 1 || list[0].Username != "alice" || !list[0].UserDeleted {
			t.Fatalf("the list after the delete: %+v %v", list, err)
		}
		labels, err := r.ResolveNames(ctx, "session", []string{s.ID})
		if err != nil || labels[s.ID] != "alice → box (SSH)" {
			t.Fatalf("the audit label after the delete: %v %v", labels, err)
		}
		var views int
		var username, display string
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*), MAX(user_username), MAX(user_display_name) FROM recording_views WHERE user_id = 'u1'`).Scan(&views, &username, &display); err != nil {
			t.Fatal(err)
		}
		if views != 1 || username != "alice" || display != "Alice Doe" {
			t.Fatalf("the recording view after the delete: %d %q %q", views, username, display)
		}

		// The same username, created again, is someone else to the old record.
		if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u2', 'alice', 'Another Alice', ?, ?)`),
			store.TimeArg(time.Now()), store.TimeArg(time.Now())); err != nil {
			t.Fatal(err)
		}
		if got, _ := r.Get(ctx, s.ID); got.UserID != "u1" || !got.UserDeleted || got.Username != "alice" {
			t.Fatalf("an account made later with the same name must not take the old history: %+v", got)
		}
		if mine, _, _ := r.List(ctx, Filter{UserID: "u2"}); len(mine) != 0 {
			t.Fatalf("the new account inherited sessions: %+v", mine)
		}
	})
}

// Nothing but the repository stops a row from naming an account that never
// existed now that there is no foreign key, so it refuses it.
func TestAnUnknownAccountOpensNothing(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		seedPerson(t, db)
		r := NewRepo(db)
		if err := r.Start(ctx, &Session{UserID: "nobody", TargetID: "t1", Protocol: "ssh", ClientIP: "x"}); !errors.Is(err, ErrUnknownUser) {
			t.Fatalf("a session for an unknown account: %v", err)
		}
		s := &Session{UserID: "u1", TargetID: "t1", Protocol: "ssh", ClientIP: "x"}
		if err := r.Start(ctx, s); err != nil {
			t.Fatal(err)
		}
		rec := &Recording{SessionID: s.ID, Format: "asciicast", StorageURI: "file:///tmp/x.cast"}
		if err := r.CreateRecording(ctx, rec); err != nil {
			t.Fatal(err)
		}
		if err := r.RecordView(ctx, rec.ID, "nobody", "x"); !errors.Is(err, ErrUnknownUser) {
			t.Fatalf("a view by an unknown account: %v", err)
		}
	})
}

// On each backend, a gateway upgraded from the schema that restricted the
// delete keeps every session and view it had, gains the name each was made
// under, and can then delete the account.
func TestMigrationLetsAnAccountWithHistoryBeDeleted(t *testing.T) {
	storetest.ForEachBackendUpTo(t, lastWithUserRestrict, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		seedPerson(t, db)
		now := store.TimeArg(time.Now())
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO access_sessions (id, user_id, target_id, protocol, client_ip, started_at, end_detail) VALUES ('s1', 'u1', 't1', 'ssh', '10.0.0.1', ?, 'kept')`, []any{now}},
			{`INSERT INTO recordings (id, session_id, format, storage_uri, started_at, created_at) VALUES ('r1', 's1', 'asciicast', 'file:///x', ?, ?)`, []any{now, now}},
			{`INSERT INTO recording_views (id, recording_id, user_id, ip, viewed_at) VALUES ('v1', 'r1', 'u1', '10.0.0.9', ?)`, []any{now}},
		} {
			if _, err := db.ExecContext(ctx, db.Rebind(q.sql), q.args...); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = 'u1'`); err == nil {
			t.Fatal("before the migration the delete was restricted")
		}

		if ran, err := store.MigrateTo(ctx, db, usersDeletable); err != nil || len(ran) != 1 || ran[0] != usersDeletable {
			t.Fatalf("migrate: ran %v, err %v", ran, err)
		}

		r := NewRepo(db)
		if got, err := r.Get(ctx, "s1"); err != nil || got.Username != "alice" || got.UserDeleted || got.EndDetail != "kept" || got.RecordingID != "r1" {
			t.Fatalf("the session after the migration: %+v %v", got, err)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = 'u1'`); err != nil {
			t.Fatalf("after the migration the account deletes: %v", err)
		}
		got, err := r.Get(ctx, "s1")
		if err != nil || got.Username != "alice" || !got.UserDeleted || got.RecordingID != "r1" {
			t.Fatalf("the session after the delete: %+v %v", got, err)
		}
		var username, display string
		if err := db.QueryRowContext(ctx, `SELECT user_username, user_display_name FROM recording_views WHERE id = 'v1'`).Scan(&username, &display); err != nil || username != "alice" || display != "Alice Doe" {
			t.Fatalf("the view's copy: %q %q %v", username, display, err)
		}
	})
}

// On each backend, the audit log still says who a deleted person was: the
// events they acted in name them, marked as deleted, from the user.delete
// event that recorded the name; an account deleted before that event carried
// a name is named from the copy on its sessions; and the log can still be
// filtered by the name they had. A live account is named plainly, and a name
// nobody had matches nothing.
func TestAuditStillNamesADeletedPerson(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		seedPerson(t, db)
		now := store.TimeArg(time.Now())
		if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u2', 'bob', 'Bob', ?, ?)`), now, now); err != nil {
			t.Fatal(err)
		}
		r := NewRepo(db)
		if err := r.Start(ctx, &Session{UserID: "u1", TargetID: "t1", Protocol: "ssh", ClientIP: "x"}); err != nil {
			t.Fatal(err)
		}
		log := audit.NewLog(db)
		if _, err := log.Record(ctx, audit.Actor{UserID: "u2", IP: "x"}.Event(audit.UserDelete, "user", "u9", audit.Success, map[string]any{"username": "carol"})); err != nil {
			t.Fatal(err)
		}
		if _, err := log.Record(ctx, audit.Actor{UserID: "u2", IP: "x"}.Event(audit.UserDelete, "user", "u1", audit.Success, map[string]any{"username": "alice"})); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = 'u1'`); err != nil {
			t.Fatal(err)
		}

		names, err := r.ResolveNames(ctx, "user", []string{"u1", "u2", "u9", "u0"})
		if err != nil {
			t.Fatal(err)
		}
		if names["u1"] != "alice (deleted)" || names["u2"] != "bob" || names["u9"] != "carol (deleted)" {
			t.Fatalf("names: %v", names)
		}
		if _, ok := names["u0"]; ok {
			t.Fatalf("an id nobody ever had must stay unnamed: %v", names)
		}

		if id, err := r.UserIDByUsername(ctx, "Carol"); err != nil || id != "u9" {
			t.Fatalf("the log filtered by a deleted name: %q %v", id, err)
		}
		if id, err := r.UserIDByUsername(ctx, "bob"); err != nil || id != "u2" {
			t.Fatalf("a live name: %q %v", id, err)
		}
		if id, err := r.UserIDByUsername(ctx, "nobody"); err != nil || id != "" {
			t.Fatalf("a name nobody had: %q %v", id, err)
		}
		// The session list filters by the name a deleted person had.
		if list, _, err := r.List(ctx, Filter{Username: "alice"}); err != nil || len(list) != 1 || !list[0].UserDeleted {
			t.Fatalf("the session list filtered by a deleted name: %+v %v", list, err)
		}

		// With no event to say, the copy on the person's session names them.
		if _, err := db.ExecContext(ctx, `DELETE FROM audit_events WHERE object_id = 'u1'`); err != nil {
			t.Fatal(err)
		}
		if names, _ := r.ResolveNames(ctx, "user", []string{"u1"}); names["u1"] != "alice (deleted)" {
			t.Fatalf("named from the session copy: %v", names)
		}
	})
}
