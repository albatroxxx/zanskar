// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// sweepRig is four sessions of one user: open and not run by the gateway,
// open and run by it, open and not run but only just started, and ended. The
// abandoned one has a recording whose bytes are in storage, left unfinished as
// a bridge whose close never ran leaves it; the young one a recording whose
// blob is gone.
type sweepRig struct {
	r                              *Repo
	db                             *store.DB
	st                             *recording.LocalStorage
	abandoned, running, young, old string
	abandonedRec, youngRec         string
	blob                           []byte
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
	rig := &sweepRig{r: NewRepo(db), db: db, st: &recording.LocalStorage{Dir: t.TempDir()}}
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
	rig.blob = []byte("{\"version\": 2}\n[0.1, \"o\", \"hello\"]\n")
	w, uri, err := rig.st.Create(ctx, rig.abandoned+".cast")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(rig.blob); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	rec := &Recording{SessionID: rig.abandoned, Format: "asciicast", StorageURI: uri}
	if err := rig.r.CreateRecording(ctx, rec); err != nil {
		t.Fatal(err)
	}
	rig.abandonedRec = rec.ID
	gone := &Recording{SessionID: rig.young, Format: "asciicast", StorageURI: "file://" + filepath.Join(rig.st.Dir, "gone.cast")}
	if err := rig.r.CreateRecording(ctx, gone); err != nil {
		t.Fatal(err)
	}
	rig.youngRec = gone.ID
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

// recordingState is a recording row's size, digest and whether it finished.
func (rig *sweepRig) recordingState(t *testing.T, id string) (size int64, sum string, finished bool) {
	t.Helper()
	var fin store.NullTime
	var sha *string
	if err := rig.db.QueryRowContext(context.Background(), rig.db.Rebind(`SELECT size_bytes, sha256, finished_at FROM recordings WHERE id = ?`), id).Scan(&size, &sha, &fin); err != nil {
		t.Fatal(err)
	}
	if sha != nil {
		sum = *sha
	}
	return size, sum, fin.Valid
}

// sweepEvent is one audit event as the tests read it.
type sweepEvent struct {
	actorIP string
	details map[string]string
}

// events lists the audit events of one action on one object.
func (rig *sweepRig) events(t *testing.T, action, objectID string) []sweepEvent {
	t.Helper()
	rows, err := rig.db.QueryContext(context.Background(), rig.db.Rebind(`SELECT actor_ip, details FROM audit_events WHERE action = ? AND object_id = ? ORDER BY id`), action, objectID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []sweepEvent
	for rows.Next() {
		var e sweepEvent
		var raw []byte
		if err := rows.Scan(&e.actorIP, &raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &e.details); err != nil {
			t.Fatalf("details %s: %v", raw, err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func newSweeper(rig *sweepRig, live func(string) bool) *Sweeper {
	return &Sweeper{Repo: rig.r, Live: live, Storage: rig.st, Audit: audit.NewLog(rig.db), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Grace: time.Millisecond}
}

// TestEndAbandoned (live, 2026-11-05): a session whose row stayed open because
// the write that ends it failed was listed as live for as long as the gateway
// ran. A row older than the cutoff that the gateway does not run is closed,
// with whose it was for the event that says so; one it runs, one newer than
// the cutoff, and one already ended are left as they are.
func TestEndAbandoned(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		rig := newSweepRig(t, db)
		live := func(id string) bool { return id == rig.running }

		// Every row is newer than a cutoff a minute ago: nothing is old enough.
		if ended, err := rig.r.EndAbandoned(ctx, time.Now().Add(-time.Minute), live, EndError, "lost"); err != nil || len(ended) != 0 {
			t.Fatalf("before the cutoff: %v %v", ended, err)
		}
		// A minute on, all of them are older than the cutoff.
		ended, err := rig.r.EndAbandoned(ctx, time.Now().Add(time.Minute), live, EndError, "the gateway lost track of this session")
		if err != nil {
			t.Fatal(err)
		}
		if len(ended) != 2 {
			t.Fatalf("ended %v, want the abandoned and the young one (not the running, not the ended)", ended)
		}
		for _, a := range ended {
			if a.UserID != "u1" || a.TargetID != "t1" {
				t.Fatalf("ended %+v: whose it was is missing", a)
			}
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
		if ended, err := rig.r.EndAbandoned(ctx, time.Now().Add(time.Minute), live, EndError, "x"); err != nil || len(ended) != 0 {
			t.Fatalf("second pass: %v %v", ended, err)
		}
		// And the dashboard's count agrees: one open, the running one.
		if c, err := rig.r.Count(ctx, time.Now().Add(-time.Hour)); err != nil || c.Open != 1 {
			t.Fatalf("open: %+v %v", c, err)
		}
	})
}

// TestSweeper: the startup pass closes what the process before it left open as
// a restart; a later pass closes a row open past Grace that the registry does
// not hold, as an error. Each end is said in the audit log by the gateway
// itself, with whose session it was, and a recording a swept session left is
// finished from what storage holds, so retention and the output index take
// it; one whose blob is gone stays unfinished and its loss is audited.
func TestSweeper(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		rig := newSweepRig(t, db)
		sw := newSweeper(rig, func(string) bool { return false })

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

		// The recording with its bytes in storage is finished as its bridge
		// would have finished it: the bytes' size and digest.
		want := sha256.Sum256(rig.blob)
		if size, sum, finished := rig.recordingState(t, rig.abandonedRec); !finished || size != int64(len(rig.blob)) || sum != hex.EncodeToString(want[:]) {
			t.Fatalf("the abandoned session's recording: finished %v, %d bytes, %q", finished, size, sum)
		}
		// The one whose blob is gone is not: that would read as an empty
		// recording (B14). Its loss is audited instead.
		if _, _, finished := rig.recordingState(t, rig.youngRec); finished {
			t.Fatal("a recording whose blob is gone was marked finished")
		}
		lost := rig.events(t, audit.RecordingLost, rig.youngRec)
		if len(lost) != 1 || lost[0].actorIP != "system" || lost[0].details["session_id"] != rig.young || lost[0].details["error"] == "" {
			t.Fatalf("recording.lost events: %+v", lost)
		}

		// The end events: the gateway the actor, as the other sweeps record
		// theirs, with whose session it was and what became of its recording.
		ends := rig.events(t, audit.SessionEnd, rig.abandoned)
		if len(ends) != 1 {
			t.Fatalf("session.end events for the abandoned session: %+v", ends)
		}
		e := ends[0]
		if e.actorIP != "system" || e.details["reason"] != EndGatewayRestart || e.details["user_id"] != "u1" || e.details["target_id"] != "t1" || e.details["recording"] != "finished from what storage holds" {
			t.Fatalf("the abandoned session's end event: %q %v", e.actorIP, e.details)
		}
		if ends := rig.events(t, audit.SessionEnd, rig.young); len(ends) != 1 || !strings.HasPrefix(ends[0].details["recording"], "lost: ") {
			t.Fatalf("the young session's end event: %+v", ends)
		}
		if ends := rig.events(t, audit.SessionEnd, rig.running); len(ends) != 1 || ends[0].details["recording"] != "" {
			t.Fatalf("a session with no recording: %+v", ends)
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

// TestSweeperLeavesAStartingSession: a row Live vouches for is not ended,
// however old: a session still being set up, an application pulling its
// images for minutes, is this gateway's although the registry does not hold
// it yet.
func TestSweeperLeavesAStartingSession(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		rig := newSweepRig(t, db)
		sw := newSweeper(rig, func(id string) bool { return id == rig.young })
		time.Sleep(5 * time.Millisecond)
		sw.Pass(context.Background())
		if ended, _ := rig.state(t, rig.young); ended {
			t.Fatal("a session still being set up was ended")
		}
		if ended, _ := rig.state(t, rig.abandoned); !ended {
			t.Fatal("the abandoned session was left open")
		}
	})
}

// TestSweeperSaysWhatItEndedWhenCutShort: a shutdown that ends the pass's
// context after rows were closed does not lose their events or leave their
// recordings unfinished; the writes run on under a bound of their own. A row
// closed without its event would leave the audit log and the row disagreeing
// for good.
func TestSweeperSaysWhatItEndedWhenCutShort(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		rig := newSweepRig(t, db)
		sw := newSweeper(rig, func(string) bool { return false })
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		sw.said(ctx, []Abandoned{{ID: rig.abandoned, UserID: "u1", TargetID: "t1"}}, EndError, "the gateway lost track of this session")
		if ends := rig.events(t, audit.SessionEnd, rig.abandoned); len(ends) != 1 || ends[0].details["detail"] != "the gateway lost track of this session" {
			t.Fatalf("session.end after the context ended: %+v", ends)
		}
		if _, _, finished := rig.recordingState(t, rig.abandonedRec); !finished {
			t.Fatal("the recording was left unfinished after the context ended")
		}
	})
}
