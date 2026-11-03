// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// 2026-11-03, idea 5 (ADR 0041 amendment): what a terminal session printed
// is found as well as what was typed, with the command it followed, while
// the setting keeps it indexed; and nothing printed stays searchable once
// retention deletes the recording or the setting is turned off.

func TestOutputSearch(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		now := store.TimeArg(time.Now())
		for _, q := range []string{
			`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1', 'alice', 'Alice', ?, ?)`,
			`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t1', 'web-1', '10.0.0.5', 'linux', ?, ?)`,
		} {
			if _, err := db.ExecContext(ctx, db.Rebind(q), now, now); err != nil {
				t.Fatal(err)
			}
		}
		r := NewRepo(db)
		s := &Session{UserID: "u1", TargetID: "t1", Protocol: "ssh", ClientIP: "10.0.0.1"}
		if err := r.Start(ctx, s); err != nil {
			t.Fatal(err)
		}
		rec := &Recording{SessionID: s.ID, Format: "asciicast", StorageURI: "file:///x.cast"}
		if err := r.CreateRecording(ctx, rec); err != nil {
			t.Fatal(err)
		}
		if err := r.FinishRecording(ctx, rec.ID, 10, "abc"); err != nil {
			t.Fatal(err)
		}
		if err := r.IndexCommands(ctx, rec.ID, []recording.Marker{
			{At: 2 * time.Second, Label: "systemctl status nginx"},
			{At: 5 * time.Second, Label: "cat /tmp/100%_report"},
		}); err != nil {
			t.Fatal(err)
		}
		if err := r.IndexOutput(ctx, rec.ID, []recording.OutputLine{
			{At: time.Second, Text: "Welcome to web-1"},
			{At: 3 * time.Second, Text: "   Active: failed (Result: exit-code)"},
			{At: 6 * time.Second, Text: "disk at 100%_full"},
		}); err != nil {
			t.Fatal(err)
		}
		find := func(q string) []OutputHit {
			t.Helper()
			hits, err := r.SearchOutput(ctx, q, 50)
			if err != nil {
				t.Fatal(err)
			}
			return hits
		}
		hits := find("ACTIVE: FAILED")
		if len(hits) != 1 || hits[0].AtMS != 3000 || hits[0].After != "systemctl status nginx" || hits[0].Username != "alice" || hits[0].TargetName != "web-1" || hits[0].RecordingID != rec.ID {
			t.Fatalf("failed: %+v", hits)
		}
		// Printed before any command: it follows nothing.
		if hits := find("welcome"); len(hits) != 1 || hits[0].After != "" {
			t.Fatalf("welcome: %+v", hits)
		}
		// % and _ are the term's own.
		if hits := find("0%_f"); len(hits) != 1 || hits[0].After != "cat /tmp/100%_report" {
			t.Fatalf("a literal %%_: %+v", hits)
		}
		if hits := find("0%f"); len(hits) != 0 {
			t.Fatalf("%% matched as a wildcard: %+v", hits)
		}
		// Indexed again, the old lines go.
		if err := r.IndexOutput(ctx, rec.ID, []recording.OutputLine{{At: time.Second, Text: "only this"}}); err != nil {
			t.Fatal(err)
		}
		if hits := find("failed"); len(hits) != 0 {
			t.Fatalf("lines from an earlier index stay: %+v", hits)
		}
		// The indexer's to-do list, on each engine: done for both, then
		// output forgotten (the setting off), then due for output alone.
		todo := func(output bool) []unindexed {
			t.Helper()
			u, err := r.unindexedCasts(ctx, 10, output)
			if err != nil {
				t.Fatal(err)
			}
			return u
		}
		if u := todo(true); len(u) != 0 {
			t.Fatalf("indexed for both, still due: %+v", u)
		}
		if err := r.forgetAllOutput(ctx); err != nil {
			t.Fatal(err)
		}
		if u := todo(false); len(u) != 0 {
			t.Fatalf("commands-only pass after forgetting output: %+v", u)
		}
		if u := todo(true); len(u) != 1 || !u[0].commands || u[0].output {
			t.Fatalf("output due again: %+v", u)
		}
		if hits := find("only this"); len(hits) != 0 {
			t.Fatalf("forgotten output still found: %+v", hits)
		}
		// Deleted by retention: nothing printed is left to find.
		if ok, err := r.markRecordingPurged(ctx, rec.ID, rec.StorageURI, time.Now()); err != nil || !ok {
			t.Fatal(ok, err)
		}
		var n int
		if err := db.QueryRowContext(ctx, db.Rebind(`SELECT COUNT(*) FROM recording_output WHERE recording_id = ?`), rec.ID).Scan(&n); err != nil || n != 0 {
			t.Fatalf("the purged recording's output stays: %d %v", n, err)
		}
	})
}

// countingStorage counts the reads of recordings.
type countingStorage struct {
	recording.Storage
	opens atomic.Int32
}

func (c *countingStorage) Open(ctx context.Context, uri string) (io.ReadCloser, error) {
	c.opens.Add(1)
	return c.Storage.Open(ctx, uri)
}

// printed records a finished terminal session that printed output.
func (e *env) printed(t *testing.T, output string) string {
	t.Helper()
	id := e.record(t, "guac") // a session and its row; the file is replaced below
	ctx := context.Background()
	cast, uri, err := recording.NewAsciicast(ctx, e.storage, id+".cast", recording.Header{Width: 80, Height: 24})
	if err != nil {
		t.Fatal(err)
	}
	_ = cast.Marker("journalctl -u nginx")
	_ = cast.Output([]byte(output))
	if _, _, err := cast.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.ExecContext(ctx, e.db.Rebind(`UPDATE recordings SET format = 'asciicast', storage_uri = ? WHERE id = ?`), uri, id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestOutputIndexFollowsTheSetting(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	recID := e.printed(t, "Nov 03 \x1b[31mnginx[812]: bind() to 0.0.0.0:443 failed\x1b[0m\r\n")
	var on atomic.Bool
	on.Store(true)
	e.h.IndexOutput = on.Load
	st := &countingStorage{Storage: e.storage}
	x := &CommandIndexer{Repo: e.repo, Storage: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), IndexOutput: on.Load}

	if n, err := x.Pass(ctx); err != nil || n != 1 || st.opens.Load() != 1 {
		t.Fatalf("a new recording is read once for both: read %d (%v), opened %d", n, err, st.opens.Load())
	}
	if n, _ := x.Pass(ctx); n != 0 {
		t.Fatalf("a second pass read %d again", n)
	}
	rr, body := e.get("/api/v1/recordings/search?q=BIND()&in=output", "reviewer")
	if rr.Code != 200 {
		t.Fatalf("search: %d %s", rr.Code, rr.Body)
	}
	items := body["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("hits: %v", items)
	}
	hit := items[0].(map[string]any)
	if hit["recording_id"] != recID || hit["after"] != "journalctl -u nginx" || !strings.Contains(hit["line"].(string), "bind() to 0.0.0.0:443 failed") || strings.Contains(hit["line"].(string), "\x1b") {
		t.Fatalf("hit: %v", hit)
	}
	evs, _, _ := e.audit.List(ctx, audit.Filter{Action: audit.RecordingSearch})
	if len(evs) != 1 || !strings.Contains(string(evs[0].Details), `"in":"output"`) || !strings.Contains(string(evs[0].Details), `"q":"BIND()"`) {
		t.Fatalf("recording.search: %v", evs)
	}
	// Commands are the default, as before.
	if rr, body := e.get("/api/v1/recordings/search?q=journalctl", "reviewer"); rr.Code != 200 || len(body["items"].([]any)) != 1 {
		t.Fatalf("commands: %d %v", rr.Code, body)
	}
	if rr, _ := e.get("/api/v1/recordings/search?q=bind&in=everything", "reviewer"); rr.Code != 400 {
		t.Fatalf("an unknown in: %d", rr.Code)
	}
	if rr, _ := e.get("/api/v1/recordings/search?q=bind&in=output", "alice"); rr.Code != 403 {
		t.Fatalf("a user searched what was printed: %d", rr.Code)
	}

	// Off: the index is emptied and the search says why it has nothing.
	on.Store(false)
	if _, err := x.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := e.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM recording_output`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("off leaves %d lines (%v)", n, err)
	}
	if rr, body := e.get("/api/v1/recordings/search?q=bind&in=output", "reviewer"); rr.Code != 409 || body["code"] != "output_not_indexed" {
		t.Fatalf("searching output while off: %d %v", rr.Code, body)
	}
	if rr, _ := e.get("/api/v1/recordings/search?q=journalctl", "reviewer"); rr.Code != 200 {
		t.Fatalf("commands while off: %d", rr.Code)
	}
	// On again: read again, for the output alone.
	on.Store(true)
	before := st.opens.Load()
	if n, err := x.Pass(ctx); err != nil || n != 1 || st.opens.Load() != before+1 {
		t.Fatalf("on again: read %d (%v)", n, err)
	}
	if rr, body := e.get("/api/v1/recordings/search?q=bind&in=output", "reviewer"); rr.Code != 200 || len(body["items"].([]any)) != 1 {
		t.Fatalf("after on again: %d %v", rr.Code, body)
	}
	var cmds int
	if err := e.db.QueryRowContext(ctx, e.db.Rebind(`SELECT COUNT(*) FROM recording_commands WHERE recording_id = ?`), recID).Scan(&cmds); err != nil || cmds != 1 {
		t.Fatalf("the commands were indexed once, not twice: %d %v", cmds, err)
	}

	// Read again for its output alone, a recording whose file has gone
	// keeps the commands found when it could be read.
	on.Store(false)
	if _, err := x.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.ExecContext(ctx, e.db.Rebind(`UPDATE recordings SET storage_uri = 'file:///nowhere.cast' WHERE id = ?`), recID); err != nil {
		t.Fatal(err)
	}
	on.Store(true)
	if n, err := x.Pass(ctx); err != nil || n != 1 {
		t.Fatalf("on again, file gone: %d %v", n, err)
	}
	if err := e.db.QueryRowContext(ctx, e.db.Rebind(`SELECT COUNT(*) FROM recording_commands WHERE recording_id = ?`), recID).Scan(&cmds); err != nil || cmds != 1 {
		t.Fatalf("an output-only read wiped the commands: %d %v", cmds, err)
	}
}

// With no setting wired (nil), commands alone are indexed, as in 1.15.0.
func TestNoSettingIndexesCommandsOnly(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.printed(t, "some output line\r\n")
	x := &CommandIndexer{Repo: e.repo, Storage: e.storage, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if n, err := x.Pass(ctx); err != nil || n != 1 {
		t.Fatalf("pass: %d %v", n, err)
	}
	var n int
	if err := e.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM recording_output`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("output indexed without the setting: %d %v", n, err)
	}
}
