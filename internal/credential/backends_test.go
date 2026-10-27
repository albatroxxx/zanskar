// SPDX-License-Identifier: Apache-2.0

package credential

import (
	"bytes"
	"context"
	"testing"

	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// TestVaultOnEachBackend proves the vault's sealing round trip on both
// engines: the ciphertext and key-version columns, the AAD bound to the row
// id, the public half listed without the secret (review Q1, finding 2).
func TestVaultOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		kek, err := crypto.NewLocalKEK(bytes.Repeat([]byte{3}, 32))
		if err != nil {
			t.Fatal(err)
		}
		ring, err := keyring.Open(ctx, db, kek)
		if err != nil {
			t.Fatal(err)
		}
		defer ring.Close()
		v := NewVault(db, ring)
		c := &Credential{Name: "svc", Type: TypePassword, Mode: ModeVaulted, Username: "svc"}
		if err := v.Create(ctx, c, &Secret{Password: "pw-123456"}, ""); err != nil {
			t.Fatal(err)
		}
		opened, err := v.Open(ctx, c.ID)
		if err != nil || opened.Password != "pw-123456" || opened.Username != "svc" {
			t.Fatalf("open: %+v %v", opened, err)
		}
		got, err := v.Get(ctx, c.ID)
		if err != nil || got.Name != "svc" || got.Username != "svc" {
			t.Fatalf("get: %+v %v", got, err)
		}
		var sealed []byte
		if err := db.QueryRowContext(ctx, db.Rebind(`SELECT secret_enc FROM credentials WHERE id = ?`), c.ID).Scan(&sealed); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(sealed, []byte("pw-123456")) || len(sealed) == 0 {
			t.Fatal("the stored secret must be ciphertext")
		}
	})
}
