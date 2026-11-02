// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/store"
)

// hiddenInput is the marker the gateway writes for input the remote did not
// echo; there is nothing to search in it (ADR 0041).
const hiddenInput = "(hidden input)"

// maxIndexedCommand bounds one command line in the index; a longer one is
// cut, the recording keeping it whole.
const maxIndexedCommand = 2000

// CommandHit is one command line a search found, with the session it was
// typed in (ADR 0041).
type CommandHit struct {
	RecordingID string    `json:"recording_id"`
	SessionID   string    `json:"session_id"`
	Username    string    `json:"username,omitempty"`
	TargetName  string    `json:"target_name,omitempty"`
	Protocol    string    `json:"protocol"`
	StartedAt   time.Time `json:"started_at"`
	// Seq is the command's marker index, which the player seeks to.
	Seq     int    `json:"seq"`
	AtMS    int64  `json:"at_ms"`
	Command string `json:"command"`
}

type unindexed struct{ id, uri string }

// unindexedCasts lists finished terminal recordings the indexer has not read,
// oldest first; purged ones are gone and are never read.
func (r *Repo) unindexedCasts(ctx context.Context, limit int) ([]unindexed, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT id, storage_uri FROM recordings
		WHERE format = 'asciicast' AND finished_at IS NOT NULL AND purged_at IS NULL AND commands_indexed = ? ORDER BY finished_at LIMIT ?`), false, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []unindexed
	for rows.Next() {
		var u unindexed
		if err := rows.Scan(&u.id, &u.uri); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// IndexCommands stores a recording's command lines and marks it indexed, in
// one transaction; hidden input is counted (seq) but not stored.
func (r *Repo) IndexCommands(ctx context.Context, recordingID string, markers []recording.Marker) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, r.db.Rebind(`DELETE FROM recording_commands WHERE recording_id = ?`), recordingID); err != nil {
		return err
	}
	for i, m := range markers {
		cmd := strings.TrimSpace(m.Label)
		if cmd == "" || cmd == hiddenInput {
			continue
		}
		if len(cmd) > maxIndexedCommand {
			cmd = strings.ToValidUTF8(cmd[:maxIndexedCommand], "")
		}
		if _, err := tx.ExecContext(ctx, r.db.Rebind(`INSERT INTO recording_commands (recording_id, seq, at_ms, command) VALUES (?, ?, ?, ?)`),
			recordingID, i, m.At.Milliseconds(), cmd); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, r.db.Rebind(`UPDATE recordings SET commands_indexed = ? WHERE id = ?`), true, recordingID); err != nil {
		return err
	}
	return tx.Commit()
}

// forgetCommands drops a recording's index, when its file goes.
func (r *Repo) forgetCommands(ctx context.Context, recordingID string) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM recording_commands WHERE recording_id = ?`), recordingID)
	return err
}

// likePattern is q as a LIKE pattern matching it anywhere, its own % _ and
// \ taken literally (ESCAPE '\').
func likePattern(q string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(strings.ToLower(q)) + "%"
}

// SearchCommands finds command lines containing q, case-insensitively, in
// recordings that still exist, newest sessions first.
func (r *Repo) SearchCommands(ctx context.Context, q string, limit int) ([]CommandHit, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT c.recording_id, s.id, u.username, t.name, s.protocol, s.started_at, c.seq, c.at_ms, c.command
		FROM recording_commands c
		JOIN recordings rec ON rec.id = c.recording_id
		JOIN access_sessions s ON s.id = rec.session_id
		LEFT JOIN users u ON u.id = s.user_id
		LEFT JOIN targets t ON t.id = s.target_id
		WHERE LOWER(c.command) LIKE ? ESCAPE '\' AND rec.purged_at IS NULL
		ORDER BY s.started_at DESC, c.seq LIMIT ?`), likePattern(q), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []CommandHit{}
	for rows.Next() {
		var (
			h            CommandHit
			uname, tname sql.NullString
			started      store.NullTime
		)
		if err := rows.Scan(&h.RecordingID, &h.SessionID, &uname, &tname, &h.Protocol, &started, &h.Seq, &h.AtMS, &h.Command); err != nil {
			return nil, err
		}
		h.Username, h.TargetName, h.StartedAt = uname.String, tname.String, started.Time
		out = append(out, h)
	}
	return out, rows.Err()
}

// searchCommands answers GET /api/v1/recordings/search?q=: the command lines
// containing q, at least two characters, in recordings that still exist,
// newest sessions first (ADR 0041). A search reads recordings' content, so it
// is recorded as recording.search with what was asked and how much was found.
func (h *Handler) searchCommands(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if utf8.RuneCountInString(q) < 2 || len(q) > 200 {
		httpx.BadRequest(w, r, "q: 2 to 200 characters")
		return
	}
	limit, _ := httpx.Paging(r, 100, 500)
	hits, err := h.Repo.SearchCommands(r.Context(), q, limit)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	p, _ := auth.FromContext(r.Context())
	h.record(r, audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}.Event(audit.RecordingSearch, "recording", "", audit.Success,
		map[string]any{"q": q, "count": len(hits)}))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": hits})
}

// CommandIndexer reads finished terminal recordings back from storage and
// indexes their command lines (ADR 0041): new recordings within a pass of
// finishing, and those from before 1.15.0 once, a batch a pass.
type CommandIndexer struct {
	Repo    *Repo
	Storage recording.Storage
	Log     *slog.Logger
	// Every is the time between passes; default 30 s.
	Every time.Duration
}

// indexBatch is how many recordings one pass reads.
const indexBatch = 25

// Run passes until ctx ends.
func (x *CommandIndexer) Run(ctx context.Context) {
	every := x.Every
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, err := x.Pass(ctx); err != nil && !errors.Is(err, context.Canceled) {
			x.Log.Warn("command index pass", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Pass indexes one batch and reports how many it read. A recording whose
// file cannot be read is marked indexed with nothing, so one lost file does
// not stall the rest; its loss is the retention's and recording.lost's story.
func (x *CommandIndexer) Pass(ctx context.Context) (int, error) {
	todo, err := x.Repo.unindexedCasts(ctx, indexBatch)
	if err != nil {
		return 0, err
	}
	for _, u := range todo {
		var markers []recording.Marker
		rc, err := x.Storage.Open(ctx, u.uri)
		if err == nil {
			markers, err = recording.Markers(rc)
			_ = rc.Close()
		}
		if err != nil {
			x.Log.Warn("command index: recording unreadable; indexed as empty", "recording", u.id, "err", err)
			markers = nil
		}
		if err := x.Repo.IndexCommands(ctx, u.id, markers); err != nil {
			return 0, err
		}
	}
	return len(todo), nil
}
