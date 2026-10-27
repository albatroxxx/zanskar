// SPDX-License-Identifier: Apache-2.0

package recstorage

import (
	"bytes"
	"context"
	"testing"

	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// TestRepoOnEachBackend proves the single-row storage configuration's
// upsert (ON CONFLICT on the fixed id), the sealed secret's round trip and
// the reset on both engines (review Q1, finding 2).
func TestRepoOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		kek, err := crypto.NewLocalKEK(bytes.Repeat([]byte{6}, 32))
		if err != nil {
			t.Fatal(err)
		}
		ring, err := keyring.Open(ctx, db, kek)
		if err != nil {
			t.Fatal(err)
		}
		defer ring.Close()
		r := NewRepo(db, ring)
		if c, err := r.Get(ctx); err != nil || c != nil {
			t.Fatalf("empty: %+v %v", c, err)
		}
		if err := r.Put(ctx, Config{Bucket: "recs", Prefix: "a", Region: "us-east-1", Auth: "keys", AccessKeyID: "AKIA1", SecretAccessKey: "secret-one"}, ""); err != nil {
			t.Fatal(err)
		}
		if err := r.Put(ctx, Config{Bucket: "recs2", Prefix: "b", Region: "eu-west-1", Auth: "keys", AccessKeyID: "AKIA2", SecretAccessKey: "secret-two"}, ""); err != nil {
			t.Fatalf("the second put is an upsert: %v", err)
		}
		got, err := r.Get(ctx)
		if err != nil || got == nil || got.Bucket != "recs2" || got.Prefix != "b" || got.AccessKeyID != "AKIA2" || got.SecretAccessKey != "secret-two" {
			t.Fatalf("after two puts: %+v %v", got, err)
		}
		var n int
		var sealed []byte
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM recording_storage`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("rows = %d (%v), want 1", n, err)
		}
		if err := db.QueryRowContext(ctx, `SELECT secret_enc FROM recording_storage WHERE id = 'active'`).Scan(&sealed); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(sealed, []byte("secret-two")) || len(sealed) == 0 {
			t.Fatal("the access key secret must be stored sealed")
		}
		if err := r.Delete(ctx); err != nil {
			t.Fatal(err)
		}
		if c, err := r.Get(ctx); err != nil || c != nil {
			t.Fatalf("after reset: %+v %v", c, err)
		}
	})
}
