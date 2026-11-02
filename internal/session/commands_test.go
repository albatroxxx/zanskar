// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// 2026-11-03, idea 5 (ADR 0041): "who ran systemctl stop nginx?" answered
// across every terminal recording still kept, case-insensitively, with a
// search term's own % and _ taken literally, hidden input never stored, and
// nothing left searchable once retention deletes the recording.
func TestCommandSearch(t *testing.T) {
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
			{At: time.Second, Label: "sudo systemctl stop nginx"},
			{At: 2 * time.Second, Label: "(hidden input)"},
			{At: 3 * time.Second, Label: "echo 100%_done"},
			{At: 4 * time.Second, Label: "ls"},
		}); err != nil {
			t.Fatal(err)
		}
		find := func(q string) []CommandHit {
			t.Helper()
			hits, err := r.SearchCommands(ctx, q, 50)
			if err != nil {
				t.Fatal(err)
			}
			return hits
		}
		hits := find("SYSTEMCTL stop")
		if len(hits) != 1 || hits[0].Seq != 0 || hits[0].AtMS != 1000 || hits[0].Username != "alice" || hits[0].TargetName != "web-1" || hits[0].RecordingID != rec.ID {
			t.Fatalf("systemctl: %+v", hits)
		}
		// % and _ are the term's own, not wildcards.
		if hits := find("%"); len(hits) != 1 || hits[0].Seq != 2 {
			t.Fatalf("a literal %%: %+v", hits)
		}
		if hits := find("0%_d"); len(hits) != 1 {
			t.Fatalf("a literal %%_: %+v", hits)
		}
		if hits := find(`\`); len(hits) != 0 {
			t.Fatalf("a backslash matched: %+v", hits)
		}
		if hits := find("hidden"); len(hits) != 0 {
			t.Fatalf("hidden input was stored: %+v", hits)
		}
		// Deleted by retention: nothing left to find.
		if ok, err := r.markRecordingPurged(ctx, rec.ID, rec.StorageURI, time.Now()); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if hits := find("ls"); len(hits) != 0 {
			t.Fatalf("a purged recording is still searchable: %+v", hits)
		}
		var n int
		if err := db.QueryRowContext(ctx, db.Rebind(`SELECT COUNT(*) FROM recording_commands WHERE recording_id = ?`), rec.ID).Scan(&n); err != nil || n != 0 {
			t.Fatalf("the purged recording's commands stay: %d %v", n, err)
		}
	})
}

// The indexer reads each finished terminal recording once, from storage, and
// the search route is the reviewers', every search recorded with its term.
func TestCommandIndexerAndSearchRoute(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	recID := e.record(t, "asciicast") // markers: "ls -la", "(hidden input)"
	e.record(t, "guac")               // a desktop: nothing to index
	x := &CommandIndexer{Repo: e.repo, Storage: e.storage, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if n, err := x.Pass(ctx); err != nil || n != 1 {
		t.Fatalf("first pass read %d (%v), want the one terminal recording", n, err)
	}
	if n, _ := x.Pass(ctx); n != 0 {
		t.Fatalf("a second pass read %d again", n)
	}

	rr, body := e.get("/api/v1/recordings/search?q=LS+-LA", "reviewer")
	if rr.Code != 200 {
		t.Fatalf("search: %d %s", rr.Code, rr.Body)
	}
	items := body["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["recording_id"] != recID || items[0].(map[string]any)["seq"] != float64(0) {
		t.Fatalf("hits: %v", items)
	}
	evs, _, _ := e.audit.List(ctx, audit.Filter{Action: audit.RecordingSearch})
	if len(evs) != 1 || !strings.Contains(string(evs[0].Details), `"q":"LS -LA"`) {
		t.Fatalf("recording.search: %v", evs)
	}
	if rr, _ := e.get("/api/v1/recordings/search?q=ls", "alice"); rr.Code != 403 {
		t.Fatalf("a user searched recordings: %d", rr.Code)
	}
	if rr, _ := e.get("/api/v1/recordings/search?q=l", "reviewer"); rr.Code != 400 {
		t.Fatalf("a one-letter search: %d", rr.Code)
	}

	// A recording whose file is gone is indexed as empty, not retried for ever.
	other := e.record(t, "asciicast")
	if _, err := e.db.ExecContext(ctx, e.db.Rebind(`UPDATE recordings SET storage_uri = 'file:///nowhere.cast' WHERE id = ?`), other); err != nil {
		t.Fatal(err)
	}
	if n, err := x.Pass(ctx); err != nil || n != 1 {
		t.Fatalf("an unreadable recording: %d %v", n, err)
	}
	if n, _ := x.Pass(ctx); n != 0 {
		t.Fatal("an unreadable recording is retried every pass")
	}
}

func TestLikePattern(t *testing.T) {
	for in, want := range map[string]string{"ls": "%ls%", "100%": `%100\%%`, "a_b": `%a\_b%`, `c:\x`: `%c:\\x%`, "ABC": "%abc%"} {
		if got := likePattern(in); got != want {
			t.Errorf("likePattern(%q) = %q, want %q", in, got, want)
		}
	}
}
