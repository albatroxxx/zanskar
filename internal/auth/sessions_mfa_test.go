// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"context"
	"testing"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestMFAProvedIsNotMFAVerified, on SQLite and (when CI provides one) on
// PostgreSQL: letting a session past the second-factor step records no proof;
// proving a code records when (ADR 0027).
func TestMFAProvedIsNotMFAVerified(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		users := user.NewRepo(db)
		u := &user.User{Username: "root", DisplayName: "Root", Roles: []user.Role{user.RoleAdmin}}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		s := NewSessions(db, bytes.Repeat([]byte{7}, 32), false)
		tok, sess, err := s.Create(ctx, u.ID, "203.0.113.9", "test", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.MarkMFAVerified(ctx, sess.ID); err != nil {
			t.Fatal(err)
		}
		got, err := s.Lookup(ctx, tok)
		if err != nil {
			t.Fatal(err)
		}
		if !got.MFAVerified || !got.MFAAt.IsZero() {
			t.Fatalf("after MarkMFAVerified: verified=%v at=%v; want verified with no proof", got.MFAVerified, got.MFAAt)
		}
		if err := s.MarkMFAProved(ctx, sess.ID); err != nil {
			t.Fatal(err)
		}
		if got, err = s.Lookup(ctx, tok); err != nil || got.MFAAt.IsZero() {
			t.Fatalf("after MarkMFAProved: at=%v err=%v; want a time", got.MFAAt, err)
		}
	})
}
