// SPDX-License-Identifier: Apache-2.0

package keyring

import (
	"context"
	"sync"
	"testing"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// TestBootstrapOnlyOnce: the guard that stops a second gateway from minting
// a second key version on an empty table is reached only when two bootstraps
// race, which no earlier test simulated (review Q1, finding 1d). Here the
// bootstrap is called again on a table that already has its version, and two
// rings open at once on a fresh database; one row results either way. On
// PostgreSQL this is also the first test to take the advisory lock.
func TestBootstrapOnlyOnce(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r, err := Open(ctx, db, kek(t, 1))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		v, err := r.createVersion(ctx, true)
		if err != nil || v != 1 {
			t.Fatalf("a repeated bootstrap must report the existing version 1, got %d %v", v, err)
		}
		if n := countVersions(t, db); n != 1 {
			t.Fatalf("key_versions rows after a repeated bootstrap = %d, want 1", n)
		}
		// A real rotation still adds a row.
		if v, err := r.createVersion(ctx, false); err != nil || v != 2 {
			t.Fatalf("rotation: %d %v", v, err)
		}
		if n := countVersions(t, db); n != 2 {
			t.Fatalf("rows after a rotation = %d, want 2", n)
		}
	})

	// Two gateways start on the same empty database.
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		var wg sync.WaitGroup
		rings := make([]*Ring, 2)
		errs := make([]error, 2)
		for i := range rings {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rings[i], errs[i] = Open(ctx, db, kek(t, 1))
			}()
		}
		wg.Wait()
		for i := range rings {
			if errs[i] != nil {
				t.Fatalf("ring %d: %v", i, errs[i])
			}
			defer rings[i].Close()
			if rings[i].ActiveVersion() != 1 {
				t.Fatalf("ring %d active = %d, want 1", i, rings[i].ActiveVersion())
			}
		}
		if n := countVersions(t, db); n != 1 {
			t.Fatalf("two concurrent bootstraps left %d rows, want 1", n)
		}
		// Both rings open what the other sealed.
		ct, ver, err := rings[0].Encrypt(AAD("credentials", "x"), []byte("shared"))
		if err != nil {
			t.Fatal(err)
		}
		if pt, err := rings[1].Decrypt(AAD("credentials", "x"), ct, ver); err != nil || string(pt) != "shared" {
			t.Fatalf("the second ring must open the first ring's ciphertext: %q %v", pt, err)
		}
	})
}

func countVersions(t *testing.T, db *store.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM key_versions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
