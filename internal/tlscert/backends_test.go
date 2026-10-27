// SPDX-License-Identifier: Apache-2.0

package tlscert

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// TestRepoOnEachBackend proves the certificate row upsert (ON CONFLICT on
// kind), the sealed key's round trip and the delete on both engines (review
// Q1, finding 2).
func TestRepoOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		kek, err := crypto.NewLocalKEK(bytes.Repeat([]byte{5}, 32))
		if err != nil {
			t.Fatal(err)
		}
		ring, err := keyring.Open(ctx, db, kek)
		if err != nil {
			t.Fatal(err)
		}
		defer ring.Close()
		r := NewRepo(db, ring)
		if err := r.Put(ctx, "uploaded", "CERT-1", "KEY-1", ""); err != nil {
			t.Fatal(err)
		}
		if err := r.Put(ctx, "uploaded", "CERT-2", "KEY-2", ""); err != nil {
			t.Fatalf("the second put is an upsert: %v", err)
		}
		cert, key, err := r.Get(ctx, "uploaded")
		if err != nil || cert != "CERT-2" || key != "KEY-2" {
			t.Fatalf("after two puts: %q %q %v", cert, key, err)
		}
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tls_certificates`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("rows = %d (%v), want 1", n, err)
		}
		var sealed []byte
		if err := db.QueryRowContext(ctx, db.Rebind(`SELECT key_enc FROM tls_certificates WHERE kind = ?`), "uploaded").Scan(&sealed); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(sealed, []byte("KEY-2")) {
			t.Fatal("the private key must be stored sealed")
		}
		if pem, err := r.GetCertPEM(ctx, "uploaded"); err != nil || pem != "CERT-2" {
			t.Fatalf("cert pem: %q %v", pem, err)
		}
		if err := r.Delete(ctx, "uploaded"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.Get(ctx, "uploaded"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("after delete: %v", err)
		}
	})
}
