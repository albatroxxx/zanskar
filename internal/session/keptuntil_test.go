// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"testing"
	"time"
)

// keptUntil follows the sweeper's rule (selectForPurge): a recording's own
// date wins, else the global age counts from when it finished; nothing is
// said for a recording that is gone, still being written, or kept forever.
func TestKeptUntil(t *testing.T) {
	fin := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	own := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	day := RetentionPolicy{MaxAgeDays: 1}
	for _, c := range []struct {
		name          string
		own, finished *time.Time
		purged        bool
		p             RetentionPolicy
		want          *time.Time
	}{
		{"own date wins over the global age", &own, &fin, false, day, &own},
		{"global age from the finish", nil, &fin, false, day, new(fin.AddDate(0, 0, 1))},
		{"no age limit", nil, &fin, false, RetentionPolicy{}, nil},
		{"still being written", nil, nil, false, day, nil},
		{"already deleted", &own, &fin, true, day, nil},
	} {
		got := keptUntil(c.own, c.finished, c.purged, c.p)
		if (got == nil) != (c.want == nil) || (got != nil && !got.Equal(*c.want)) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// The reviewers' list says when each recording goes and which are gone; the
// person's own list says nothing about recordings (ADR 0006). 2026-11-03
// live audit, Q10: the global policy said 1 day while October recordings
// stayed, kept by their own dates, and no page said so.
func TestSessionsSayWhenRecordingsGo(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	kept := e.record(t, "asciicast")
	gone := e.record(t, "asciicast")
	if err := e.repo.SetRetentionPolicy(ctx, RetentionPolicy{MaxAgeDays: 3}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.repo.markRecordingPurged(ctx, gone, mustURI(t, e, gone), time.Now()); err != nil {
		t.Fatal(err)
	}
	rr, body := e.get("/api/v1/sessions", "reviewer")
	if rr.Code != 200 {
		t.Fatalf("list: %d %s", rr.Code, rr.Body)
	}
	byRec := map[string]map[string]any{}
	for _, it := range body["items"].([]any) {
		m := it.(map[string]any)
		byRec[m["recording_id"].(string)] = m
	}
	until, ok := byRec[kept]["recording_kept_until"].(string)
	if !ok {
		t.Fatalf("kept recording has no date: %v", byRec[kept])
	}
	at, _ := time.Parse(time.RFC3339Nano, until)
	if d := time.Until(at); d < 71*time.Hour || d > 73*time.Hour {
		t.Fatalf("kept until %v, want about three days from now", at)
	}
	if byRec[gone]["recording_purged"] != true || byRec[gone]["recording_kept_until"] != nil {
		t.Fatalf("deleted recording: %v", byRec[gone])
	}

	_, mine := e.get("/api/v1/me/sessions", "alice")
	for _, it := range mine["items"].([]any) {
		m := it.(map[string]any)
		for _, k := range []string{"recording_id", "recording_purged", "recording_kept_until"} {
			if _, ok := m[k]; ok {
				t.Fatalf("the person's own list carries %s: %v", k, m)
			}
		}
	}
}

func mustURI(t *testing.T, e *env, id string) string {
	t.Helper()
	var uri string
	if err := e.db.QueryRowContext(context.Background(), e.db.Rebind(`SELECT storage_uri FROM recordings WHERE id = ?`), id).Scan(&uri); err != nil {
		t.Fatal(err)
	}
	return uri
}
