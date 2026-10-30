// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// TestListFromMatchesCountOnEachBackend (2026-10-30): the dashboard's
// "Sessions (24h)" opens the list started since the same moment, and the
// list holds exactly the sessions Count counted; open-only likewise. The
// timestamp comparison runs on both engines.
func TestListFromMatchesCountOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		stamp := store.TimeArg(time.Now())
		for _, q := range []string{
			`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1', 'alice', 'Alice', ?, ?)`,
			`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t1', 'box', '10.0.0.5', 'linux', ?, ?)`,
		} {
			if _, err := db.ExecContext(ctx, db.Rebind(q), stamp, stamp); err != nil {
				t.Fatal(err)
			}
		}
		r := NewRepo(db)
		var ids []string
		for range 3 {
			s := &Session{UserID: "u1", TargetID: "t1", Protocol: "ssh", ClientIP: "10.0.0.1"}
			if err := r.Start(ctx, s); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, s.ID)
		}
		// One started two days ago and ended; one ended today.
		if _, err := db.ExecContext(ctx, db.Rebind(`UPDATE access_sessions SET started_at = ?, ended_at = ? WHERE id = ?`),
			store.TimeArg(time.Now().Add(-48*time.Hour)), store.TimeArg(time.Now().Add(-47*time.Hour)), ids[0]); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, db.Rebind(`UPDATE access_sessions SET ended_at = ? WHERE id = ?`), stamp, ids[1]); err != nil {
			t.Fatal(err)
		}
		since := time.Now().Add(-24 * time.Hour)
		c, err := r.Count(ctx, since)
		if err != nil {
			t.Fatal(err)
		}
		recent, _, err := r.List(ctx, Filter{From: since})
		if err != nil || len(recent) != c.StartedSince || len(recent) != 2 {
			t.Fatalf("started since: listed %d, counted %d, %v", len(recent), c.StartedSince, err)
		}
		open, _, err := r.List(ctx, Filter{OpenOnly: true})
		if err != nil || len(open) != c.Open || len(open) != 1 || open[0].ID != ids[2] {
			t.Fatalf("open: listed %d, counted %d, %v", len(open), c.Open, err)
		}
	})
}
