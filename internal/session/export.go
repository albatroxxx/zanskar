// SPDX-License-Identifier: Apache-2.0

package session

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
)

// maxExportRows bounds one CSV export. A longer one ends with a row saying
// it was cut there, so a reader never takes a part for the whole.
var maxExportRows = 50_000

// exportPage is how many rows each query of an export reads; the queries run
// one after another, never with a cursor left open (SQLite runs on one
// connection).
var exportPage = 500

// csvCell defuses a value a spreadsheet would run as a formula: a username,
// a target name or a detail starting with = + - @ (or a tab or carriage
// return before one) is written with a leading apostrophe, which the
// spreadsheet shows as text (CSV injection, OWASP).
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func csvRow(cells ...string) []string {
	for i, c := range cells {
		cells[i] = csvCell(c)
	}
	return cells
}

// The exports' columns.
var (
	eventColumns   = []string{"id", "time", "actor", "actor_ip", "action", "outcome", "object_type", "object_id", "object_name", "details", "hash"}
	sessionColumns = []string{"id", "started", "ended", "duration_seconds", "user", "target", "protocol", "client_ip", "end_reason", "end_detail", "recording_id", "recording_kept_until"}
)

// note is a row that says something about the export itself, as wide as its
// header so a strict reader takes the file: msg in column col, the rest
// empty.
func note(header []string, col int, msg string) []string {
	row := make([]string, len(header))
	row[col] = msg
	return row
}

// startCSV sets the headers of a CSV download named for what it holds and
// the day.
func startCSV(w http.ResponseWriter, what string) *csv.Writer {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="zanskar-%s-%s.csv"`, what, time.Now().UTC().Format("2006-01-02")))
	w.Header().Set("Cache-Control", "no-store")
	return csv.NewWriter(w)
}

// exportEvents answers GET /api/v1/audit/events.csv: the events the filter
// on the Events page shows, every page of them up to maxExportRows, as CSV
// (2026-11-03, idea 12). The export is a read of the log and is recorded as
// one, with what it held.
func (h *Handler) exportEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f, err := h.auditFilter(r)
	if err != nil {
		h.failFilter(w, r, err)
		return
	}
	var (
		cw        *csv.Writer
		n         int
		cursor    string
		truncated bool
	)
	for {
		f.Cursor, f.Limit = cursor, exportPage
		items, next, err := h.Audit.List(ctx, f)
		if err == nil && cw == nil {
			cw = startCSV(w, "events")
			_ = cw.Write(eventColumns)
		}
		if err != nil {
			if cw == nil {
				h.fail(w, r, err)
				return
			}
			_ = cw.Write(note(eventColumns, 4, "export stopped: the log could not be read further"))
			break
		}
		rows, err := h.decorate(ctx, items)
		if err != nil {
			_ = cw.Write(note(eventColumns, 4, "export stopped: names could not be read"))
			break
		}
		for _, e := range rows {
			_ = cw.Write(csvRow(strconv.FormatInt(e.ID, 10), e.Timestamp.UTC().Format(time.RFC3339Nano), e.ActorUsername, e.ActorIP, e.Action, string(e.Outcome),
				e.ObjectType, e.ObjectID, e.ObjectName, string(e.Details), e.Hash))
		}
		n += len(rows)
		if next == "" {
			break
		}
		if n >= maxExportRows {
			truncated = true
			_ = cw.Write(note(eventColumns, 4, fmt.Sprintf("export cut at %d rows: narrow the filter for the rest", n)))
			break
		}
		cursor = next
	}
	cw.Flush()
	p, _ := auth.FromContext(ctx)
	h.record(r, audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}.Event(audit.AuditRead, "audit_log", "", audit.Success,
		map[string]any{"count": n, "format": "csv", "truncated": truncated, "filter_action": f.Action, "filter_actor": f.ActorUserID}))
}

// exportSessions answers GET /api/v1/sessions.csv: the sessions the filter
// on the Sessions page shows, as CSV (idea 12). Recorded as a read, as the
// events export is.
func (h *Handler) exportSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f, err := sessionFilter(r)
	if err != nil {
		h.failFilter(w, r, err)
		return
	}
	policy, err := h.Repo.GetRetentionPolicy(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	cw := startCSV(w, "sessions")
	_ = cw.Write(sessionColumns)
	var (
		n         int
		cursor    string
		truncated bool
	)
	for {
		f.Cursor, f.Limit = cursor, exportPage
		items, next, err := h.Repo.List(ctx, f)
		if err != nil {
			_ = cw.Write(note(sessionColumns, 0, "export stopped: sessions could not be read further"))
			break
		}
		for _, s := range items {
			s.WithRetention(policy)
			ended, dur, kept := "", "", ""
			if s.EndedAt != nil {
				ended = s.EndedAt.UTC().Format(time.RFC3339)
				dur = strconv.Itoa(int(s.EndedAt.Sub(s.StartedAt).Seconds()))
			}
			if s.RecordingKeptUntil != nil {
				kept = s.RecordingKeptUntil.UTC().Format(time.RFC3339)
			}
			target := s.TargetName
			if target == "" {
				target = strings.TrimSpace(s.ASGName + " " + s.InstanceID)
			}
			_ = cw.Write(csvRow(s.ID, s.StartedAt.UTC().Format(time.RFC3339), ended, dur, s.Username, target, s.Protocol, s.ClientIP,
				s.EndReason, s.EndDetail, s.RecordingID, kept))
		}
		n += len(items)
		if next == "" {
			break
		}
		if n >= maxExportRows {
			truncated = true
			_ = cw.Write(note(sessionColumns, 0, fmt.Sprintf("export cut at %d rows: narrow the filter for the rest", n)))
			break
		}
		cursor = next
	}
	cw.Flush()
	p, _ := auth.FromContext(ctx)
	h.record(r, audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}.Event(audit.AuditRead, "access_session", "", audit.Success,
		map[string]any{"count": n, "format": "csv", "truncated": truncated, "of": "sessions"}))
}
