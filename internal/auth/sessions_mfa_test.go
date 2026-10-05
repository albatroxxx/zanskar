// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestMFAProvedIsNotMFAVerified, on SQLite and (when CI provides one) on
// PostgreSQL: letting a session past the second-factor step records no proof;
// proving a code records when (ADR 0027).
func TestMFAProvedIsNotMFAVerified(t *testing.T) {
	type backend struct {
		name string
		open func(t *testing.T) *store.DB
	}
	backends := []backend{{"sqlite", func(t *testing.T) *store.DB {
		db, err := store.Open(context.Background(), config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
		if err != nil {
			t.Fatal(err)
		}
		return db
	}}}
	if dsn := os.Getenv("ZANSKAR_TEST_POSTGRES_DSN"); dsn != "" {
		backends = append(backends, backend{"postgres", func(t *testing.T) *store.DB { return isolatedPostgres(t, dsn) }})
	}
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			db := b.open(t)
			t.Cleanup(func() { _ = db.Close() })
			if _, err := store.Migrate(ctx, db); err != nil {
				t.Fatal(err)
			}
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
}

// isolatedPostgres opens dsn in a schema of its own, so this test cannot
// disturb other packages' tests running against the same database.
func isolatedPostgres(t *testing.T, dsn string) *store.DB {
	t.Helper()
	ctx := context.Background()
	admin, err := store.Open(ctx, config.DriverPostgres, dsn)
	if err != nil {
		t.Fatal(err)
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	schema := "auth_test_" + hex.EncodeToString(b[:])
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		_ = admin.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := store.Open(ctx, config.DriverPostgres, u.String())
	if err != nil {
		t.Fatal(err)
	}
	return db
}
