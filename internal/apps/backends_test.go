// SPDX-License-Identifier: Apache-2.0

package apps

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestRepoOnEachBackend proves the application-session repository on both
// engines: the four-way join behind every lookup, the idle and expiry
// columns, the touch and the per-session delete (review Q1, finding 2).
func TestRepoOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		users := user.NewRepo(db)
		alice := &user.User{Username: "alice", DisplayName: "Alice", Roles: []user.Role{user.RoleUser}}
		if err := users.Create(ctx, alice); err != nil {
			t.Fatal(err)
		}
		tg := &target.Target{Name: "wiki", AppUpstream: "http://10.0.0.9:3000", Tags: map[string]string{"env": "test"}}
		if err := target.NewRepo(db).Create(ctx, tg); err != nil {
			t.Fatal(err)
		}
		acc := &session.Session{UserID: alice.ID, TargetID: tg.ID, Protocol: "http", ClientIP: "10.0.0.1"}
		if err := session.NewRepo(db).Start(ctx, acc); err != nil {
			t.Fatal(err)
		}
		sessions := auth.NewSessions(db, bytes.Repeat([]byte{7}, 32), false)
		_, signIn, err := sessions.Create(ctx, alice.ID, "10.0.0.1", "test", true)
		if err != nil {
			t.Fatal(err)
		}
		r := NewRepo(db)
		exp := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
		row := &Row{TokenHash: "h1", SessionID: acc.ID, AuthSessionID: signIn.ID, UserID: alice.ID, TargetID: tg.ID, Idle: 10 * time.Minute, ExpiresAt: &exp}
		if err := r.Create(ctx, row); err != nil {
			t.Fatal(err)
		}
		got, err := r.Lookup(ctx, "h1")
		if err != nil {
			t.Fatal(err)
		}
		if got.UserID != alice.ID || got.TargetID != tg.ID || got.Idle != 10*time.Minute || got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) ||
			got.ClientIP != "10.0.0.1" || got.UserStatus != string(user.StatusActive) || got.AuthRevoked || got.Target.Upstream == "" {
			t.Fatalf("lookup: %+v target=%+v", got, got.Target)
		}
		later := time.Now().UTC().Add(time.Minute).Truncate(time.Second)
		if err := r.Touch(ctx, "h1", later); err != nil {
			t.Fatal(err)
		}
		if got, err = r.Lookup(ctx, "h1"); err != nil || !got.LastSeenAt.Equal(later) {
			t.Fatalf("after touch: %v %v", got.LastSeenAt, err)
		}
		if list, err := r.List(ctx); err != nil || len(list) != 1 {
			t.Fatalf("list: %d %v", len(list), err)
		}
		if err := r.DeleteBySession(ctx, acc.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Lookup(ctx, "h1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("after delete: %v", err)
		}
	})
}
