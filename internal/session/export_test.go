// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"encoding/csv"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
)

func readCSV(t *testing.T, body string) [][]string {
	t.Helper()
	recs, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("not CSV: %v\n%s", err, body)
	}
	return recs
}

// 2026-11-03, idea 12: the Events and Sessions lists as CSV, every page the
// filter matches, for reviewers only; each export recorded as a read.
func TestExportEvents(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	alice := e.ids["alice"]
	for i := range 7 {
		ev := audit.Actor{UserID: alice, IP: "10.0.0.1"}.Event(audit.UserLogin, "user", alice, audit.Success, map[string]any{"n": i})
		if _, err := e.audit.Record(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	// A value a spreadsheet would run as a formula.
	if _, err := e.audit.Record(ctx, audit.Actor{UserID: alice, IP: "10.0.0.1"}.Event("target.update", "target", "=HYPERLINK(\"http://x\")", audit.Failure, nil)); err != nil {
		t.Fatal(err)
	}
	defer func(p int) { exportPage = p }(exportPage)
	exportPage = 3 // several pages, read one after another

	rr, _ := e.get("/api/v1/audit/events.csv?action=user.login", "reviewer")
	if rr.Code != 200 || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/csv") || !strings.Contains(rr.Header().Get("Content-Disposition"), `filename="zanskar-events-`) {
		t.Fatalf("export: %d %v", rr.Code, rr.Header())
	}
	recs := readCSV(t, rr.Body.String())
	if len(recs) != 8 || recs[0][0] != "id" || recs[1][2] != "alice" || recs[1][4] != "user.login" {
		t.Fatalf("got %d rows: %v", len(recs), recs[:min(3, len(recs))])
	}

	rr, _ = e.get("/api/v1/audit/events.csv?outcome=failure", "root")
	recs = readCSV(t, rr.Body.String())
	if len(recs) != 2 || recs[1][7] != `'=HYPERLINK("http://x")` {
		t.Fatalf("a formula must be written as text: %v", recs)
	}

	// Cut at the cap, and the file says so.
	defer func(m int) { maxExportRows = m }(maxExportRows)
	maxExportRows = 4
	rr, _ = e.get("/api/v1/audit/events.csv?action=user.login", "reviewer")
	recs = readCSV(t, rr.Body.String())
	last := recs[len(recs)-1]
	if len(recs) != 1+6+1 || !strings.Contains(last[4], "export cut at 6 rows") {
		t.Fatalf("a cut export: %d rows, last %v", len(recs), last)
	}

	// Reviewers only.
	if rr, _ := e.get("/api/v1/audit/events.csv", "alice"); rr.Code != 403 {
		t.Fatalf("a user exported the log: %d", rr.Code)
	}
	if rr, _ := e.get("/api/v1/audit/events.csv?outcome=maybe", "root"); rr.Code != 400 {
		t.Fatalf("a bad filter: %d", rr.Code)
	}
	// Each export is a read of the log, with what it held.
	reads, _, _ := e.audit.List(ctx, audit.Filter{Action: audit.AuditRead})
	if len(reads) < 3 || !strings.Contains(string(reads[0].Details), `"format":"csv"`) || !strings.Contains(string(reads[0].Details), `"truncated":true`) {
		t.Fatalf("export reads: %v", reads)
	}
}

func TestExportSessions(t *testing.T) {
	e := newEnv(t)
	e.record(t, "asciicast")
	e.record(t, "guac")
	rr, _ := e.get("/api/v1/sessions.csv", "reviewer")
	if rr.Code != 200 {
		t.Fatalf("export: %d %s", rr.Code, rr.Body)
	}
	recs := readCSV(t, rr.Body.String())
	if len(recs) != 3 || recs[0][1] != "started" || recs[1][4] != "alice" || recs[1][5] != "web 1" || recs[1][8] != "user_exit" || recs[1][10] == "" {
		t.Fatalf("sessions: %v", recs)
	}
	if rr, _ := e.get("/api/v1/sessions.csv", "alice"); rr.Code != 403 {
		t.Fatalf("a user exported sessions: %d", rr.Code)
	}
}

func TestCSVCell(t *testing.T) {
	for in, want := range map[string]string{"=1+1": "'=1+1", "+x": "'+x", "-2": "'-2", "@SUM(A1)": "'@SUM(A1)", "\t=x": "'\t=x", "alice": "alice", "": ""} {
		if got := csvCell(in); got != want {
			t.Errorf("csvCell(%q) = %q, want %q", in, got, want)
		}
	}
}
