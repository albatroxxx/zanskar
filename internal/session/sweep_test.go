// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// sweepRig is four sessions of one user: open and not run by the gateway,
// open and run by it, open and not run but only just started, and ended.
type sweepRig struct {
	r                              *Repo
	db                             *store.DB
	abandoned, running, young, old string
}

func newSweepRig(t *testing.T, db *store.DB) *sweepRig {
	t.Helper()
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
	rig := &sweepRig{r: NewRepo(db), db: db}
	start := func() string {
		s := &Session{UserID: "u1", TargetID: "t1", Protocol: "ssh", ClientIP: "10.0.0.1"}
		if err := rig.r.Start(ctx, s); err != nil {
			t.Fatal(err)
		}
		return s.ID
	}
	rig.abandoned, rig.running, rig.young, rig.old = start(), start(), start(), start()
	if err := rig.r.End(ctx, rig.old, EndUserExit); err != nil {
		t.Fatal(err)
	}
	return rig
}

func (rig *sweepRig) state(t *testing.T, id string) (ended bool, reason string) {
	t.Helper()
	s, err := rig.r.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return s.EndedAt != nil, s.EndReason
}

// TestEndAbandoned (live, 2026-11-05): a session whose row stayed open because
// the write that ends it failed was listed as live for as long as the gateway
// ran. A row older than the cutoff that the gateway does not run is closed; one
// it runs, one newer than the cutoff, and one already ended are left as they are.
func TestEndAbandoned(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		rig := newSweepRig(t, db)
		live := func(id string) bool { return id == rig.running }

		// Every row is newer than a cutoff a minute ago: nothing is old enough.
		if ids, err := rig.r.EndAbandoned(ctx, time.Now().Add(-time.Minute), live, EndError, "lost"); err != nil || len(ids) != 0 {
			t.Fatalf("before the cutoff: %v %v", ids, err)
		}
		// A minute on, all of them are older than the cutoff.
		ids, err := rig.r.EndAbandoned(ctx, time.Now().Add(time.Minute), live, EndError, "the gateway lost track of this session")
		if err != nil {
			t.Fatal(err)
		}
		if len(ids) != 2 {
			t.Fatalf("ended %v, want the abandoned and the young one (not the running, not the ended)", ids)
		}
		if ended, reason := rig.state(t, rig.abandoned); !ended || reason != EndError {
			t.Fatalf("abandoned: %v %q", ended, reason)
		}
		if ended, _ := rig.state(t, rig.running); ended {
			t.Fatal("a session the gateway runs was ended")
		}
		if ended, reason := rig.state(t, rig.old); !ended || reason != EndUserExit {
			t.Fatalf("an ended session was rewritten: %v %q", ended, reason)
		}
		got, _ := rig.r.Get(ctx, rig.abandoned)
		if got.EndDetail != "the gateway lost track of this session" {
			t.Fatalf("detail %q", got.EndDetail)
		}
		// A second pass finds nothing more.
		if ids, err := rig.r.EndAbandoned(ctx, time.Now().Add(time.Minute), live, EndError, "x"); err != nil || len(ids) != 0 {
			t.Fatalf("second pass: %v %v", ids, err)
		}
		// And the dashboard's count agrees: one open, the running one.
		if c, err := rig.r.Count(ctx, time.Now().Add(-time.Hour)); err != nil || c.Open != 1 {
			t.Fatalf("open: %+v %v", c, err)
		}
	})
}

// TestSweeper: the startup pass closes what the process before it left open as
// a restart; a later pass closes a row open past Grace that the registry does
// not hold, as an error, and each is said in the audit log.
func TestSweeper(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		rig := newSweepRig(t, db)
		log := slog.New(slog.NewTextHandler(io.Discard, nil))
		sw := &Sweeper{Repo: rig.r, Live: func(string) bool { return false }, Audit: audit.NewLog(db), Log: log, Grace: time.Millisecond}

		// A row that began before the process did: the restart left it.
		sw.Startup(ctx, time.Now().Add(time.Minute))
		for _, id := range []string{rig.abandoned, rig.running, rig.young} {
			if ended, reason := rig.state(t, id); !ended || reason != EndGatewayRestart {
				t.Fatalf("startup pass: %v %q", ended, reason)
			}
		}
		if ended, reason := rig.state(t, rig.old); !ended || reason != EndUserExit {
			t.Fatalf("an ended session was rewritten: %v %q", ended, reason)
		}
		// A session that opens later and is never run is closed by a pass past Grace.
		s := &Session{UserID: "u1", TargetID: "t1", Protocol: "rdp", ClientIP: "10.0.0.1"}
		if err := rig.r.Start(ctx, s); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
		sw.Pass(ctx)
		if ended, reason := rig.state(t, s.ID); !ended || reason != EndError {
			t.Fatalf("later pass: %v %q", ended, reason)
		}
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE action = 'session.end'`).Scan(&n); err != nil || n != 4 {
			t.Fatalf("audit events for the ends: %d %v", n, err)
		}
	})
}
