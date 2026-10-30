// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestSessionProviderOnEachBackend (ADR 0035): a session records the
// provider it signed in through and the sealed ID token, reads them back
// after it is revoked (signing out revokes first), keeps none for a
// password sign-in, and loses the provider when the provider is deleted.
func TestSessionProviderOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		u := &user.User{Username: "kim", DisplayName: "Kim", Roles: []user.Role{user.RoleUser}}
		if err := user.NewRepo(db).Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO identity_providers (id, name, type, config_enc, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`),
			"kc", "kc", "oidc", []byte("x"), true, store.TimeArg(now), store.TimeArg(now)); err != nil {
			t.Fatal(err)
		}
		var ver int
		if err := db.QueryRowContext(ctx, `SELECT MIN(id) FROM key_versions`).Scan(&ver); err != nil {
			// A fresh schema has no key version until a ring opens; make one.
			if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO key_versions (id, algorithm, kek_source, wrapped_dek, created_at) VALUES (1, 'AES-256-GCM', 'local', ?, ?)`), []byte("w"), store.TimeArg(now)); err != nil {
				t.Fatal(err)
			}
			ver = 1
		}
		s := NewSessions(db, bytes.Repeat([]byte{1}, 32), false)
		_, sso, err := s.Create(ctx, u.ID, "10.0.0.1", "t", true)
		if err != nil {
			t.Fatal(err)
		}
		_, local, err := s.Create(ctx, u.ID, "10.0.0.1", "t", true)
		if err != nil {
			t.Fatal(err)
		}
		sealed := []byte{0, 1, 2, 250, 255}
		if err := s.SetProvider(ctx, sso.ID, "kc", sealed, ver); err != nil {
			t.Fatal(err)
		}
		if err := s.Revoke(ctx, sso.ID); err != nil {
			t.Fatal(err)
		}
		idp, enc, v, err := s.Provider(ctx, sso.ID)
		if err != nil || idp != "kc" || !bytes.Equal(enc, sealed) || v != ver {
			t.Fatalf("provider session: %q %v %d %v", idp, enc, v, err)
		}
		if idp, enc, _, err := s.Provider(ctx, local.ID); err != nil || idp != "" || enc != nil {
			t.Fatalf("password session: %q %v %v", idp, enc, err)
		}
		if _, _, _, err := s.Provider(ctx, "nope"); !errors.Is(err, ErrNoSession) {
			t.Fatalf("unknown session: %v", err)
		}
		if _, err := db.ExecContext(ctx, db.Rebind(`DELETE FROM identity_providers WHERE id = ?`), "kc"); err != nil {
			t.Fatal(err)
		}
		if idp, _, _, err := s.Provider(ctx, sso.ID); err != nil || idp != "" {
			t.Fatalf("after the provider is deleted: %q %v", idp, err)
		}
	})
}
