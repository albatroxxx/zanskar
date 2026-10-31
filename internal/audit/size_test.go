// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"

	"github.com/albatroxxx/zanskar/internal/store"
)

// TestSizeOnEachBackend (2026-10-31, the dashboard's storage tiles): an empty
// log holds nothing; recorded events are counted, and their estimated size
// is at least their two hashes each and no more than a short event can make
// it. On Postgres the timestamp and the JSONB details are read as text.
func TestSizeOnEachBackend(t *testing.T) {
	forEachBackend(t, func(t *testing.T, log *Log, _ *store.DB) {
		ctx := context.Background()
		if n, b, err := log.Size(ctx); err != nil || n != 0 || b != 0 {
			t.Fatalf("empty log: %d events, %d bytes, %v", n, b, err)
		}
		record(t, log, 3)
		n, b, err := log.Size(ctx)
		if err != nil || n != 3 || b < 3*128 || b > 3*1024 {
			t.Fatalf("three events: %d events, %d bytes, %v", n, b, err)
		}
	})
}
