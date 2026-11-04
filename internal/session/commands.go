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

// unindexed is a recording the indexer has still to read, and what of it
// is already indexed.
type unindexed struct {
	id, uri          string
	commands, output bool
}

// unindexedCasts lists finished terminal recordings the indexer has not read,
// for their commands or, with output, for what they printed; oldest first.
// Purged ones are gone and are never read.
func (r *Repo) unindexedCasts(ctx context.Context, limit int, output bool) ([]unindexed, error) {
	todo, args := `commands_indexed = ?`, []any{false}
	if output {
		todo, args = `(commands_indexed = ? OR output_indexed = ?)`, []any{false, false}
	}
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT id, storage_uri, commands_indexed, output_indexed FROM recordings
		WHERE format = 'asciicast' AND finished_at IS NOT NULL AND purged_at IS NULL AND `+todo+` ORDER BY finished_at LIMIT ?`), append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []unindexed
	for rows.Next() {
		var u unindexed
		if err := rows.Scan(&u.id, &u.uri, &u.commands, &u.output); err != nil {
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

// IndexOutput stores the lines a recording printed and marks its output
// indexed, in one transaction (2026-11-03, idea 5).
func (r *Repo) IndexOutput(ctx context.Context, recordingID string, lines []recording.OutputLine) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, r.db.Rebind(`DELETE FROM recording_output WHERE recording_id = ?`), recordingID); err != nil {
		return err
	}
	for i, l := range lines {
		if _, err := tx.ExecContext(ctx, r.db.Rebind(`INSERT INTO recording_output (recording_id, seq, at_ms, line) VALUES (?, ?, ?, ?)`),
			recordingID, i, l.At.Milliseconds(), l.Text); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, r.db.Rebind(`UPDATE recordings SET output_indexed = ? WHERE id = ?`), true, recordingID); err != nil {
		return err
	}
	return tx.Commit()
}

// forgetAllOutput empties the output index, when the setting is turned off:
// nothing printed stays searchable, and turning it on reads it all again.
func (r *Repo) forgetAllOutput(ctx context.Context) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, `DELETE FROM recording_output`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, r.db.Rebind(`UPDATE recordings SET output_indexed = ? WHERE output_indexed = ?`), false, true); err != nil {
		return err
	}
	return tx.Commit()
}

// forgetCommands drops a recording's index, commands and output, when its
// file goes.
func (r *Repo) forgetCommands(ctx context.Context, recordingID string) error {
	if _, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM recording_commands WHERE recording_id = ?`), recordingID); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM recording_output WHERE recording_id = ?`), recordingID)
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
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT c.recording_id, s.id, COALESCE(u.username, NULLIF(s.user_username, '')), t.name, s.protocol, s.started_at, c.seq, c.at_ms, c.command
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

// OutputHit is one printed line a search found, with the session it was
// printed in and the command it followed, if any (2026-11-03, idea 5).
type OutputHit struct {
	RecordingID string    `json:"recording_id"`
	SessionID   string    `json:"session_id"`
	Username    string    `json:"username,omitempty"`
	TargetName  string    `json:"target_name,omitempty"`
	Protocol    string    `json:"protocol"`
	StartedAt   time.Time `json:"started_at"`
	AtMS        int64     `json:"at_ms"`
	Line        string    `json:"line"`
	// After is the last command typed before the line was printed.
	After string `json:"after,omitempty"`
}

// SearchOutput finds printed lines containing q, case-insensitively, in
// recordings that still exist, newest sessions first. Each hit names the
// command typed last before it, read after the scan so no second query runs
// while the first's rows are open (SQLite has one connection).
func (r *Repo) SearchOutput(ctx context.Context, q string, limit int) ([]OutputHit, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	out, err := r.outputHits(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	for i := range out {
		var after sql.NullString
		err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT command FROM recording_commands WHERE recording_id = ? AND at_ms <= ? ORDER BY at_ms DESC, seq DESC LIMIT 1`),
			out[i].RecordingID, out[i].AtMS).Scan(&after)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		out[i].After = after.String
	}
	return out, nil
}

// outputHits is SearchOutput's scan, its cursor closed when it returns.
func (r *Repo) outputHits(ctx context.Context, q string, limit int) ([]OutputHit, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT o.recording_id, s.id, COALESCE(u.username, NULLIF(s.user_username, '')), t.name, s.protocol, s.started_at, o.at_ms, o.line
		FROM recording_output o
		JOIN recordings rec ON rec.id = o.recording_id
		JOIN access_sessions s ON s.id = rec.session_id
		LEFT JOIN users u ON u.id = s.user_id
		LEFT JOIN targets t ON t.id = s.target_id
		WHERE LOWER(o.line) LIKE ? ESCAPE '\' AND rec.purged_at IS NULL
		ORDER BY s.started_at DESC, o.seq LIMIT ?`), likePattern(q), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []OutputHit{}
	for rows.Next() {
		var (
			h            OutputHit
			uname, tname sql.NullString
			started      store.NullTime
		)
		if err := rows.Scan(&h.RecordingID, &h.SessionID, &uname, &tname, &h.Protocol, &started, &h.AtMS, &h.Line); err != nil {
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
	// in=output searches what sessions printed (2026-11-03, idea 5), while
	// the setting keeps it indexed; anything else, the command lines.
	in := r.URL.Query().Get("in")
	var (
		hits  any
		count int
		err   error
	)
	switch in {
	case "", "commands":
		in = "commands"
		var found []CommandHit
		found, err = h.Repo.SearchCommands(r.Context(), q, limit)
		hits, count = found, len(found)
	case "output":
		if h.IndexOutput != nil && !h.IndexOutput() {
			httpx.WriteError(w, r, http.StatusConflict, "output_not_indexed", "terminal output is not indexed: the setting Index terminal output is off")
			return
		}
		var found []OutputHit
		found, err = h.Repo.SearchOutput(r.Context(), q, limit)
		hits, count = found, len(found)
	default:
		httpx.BadRequest(w, r, "in: commands or output")
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	p, _ := auth.FromContext(r.Context())
	h.record(r, audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}.Event(audit.RecordingSearch, "recording", "", audit.Success,
		map[string]any{"q": q, "in": in, "count": count}))
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
	// IndexOutput says whether what sessions printed is indexed too (the
	// runtime setting); nil indexes commands only. Off, a pass empties the
	// output index.
	IndexOutput func() bool
}

// indexBatch is how many recordings one pass reads.
const indexBatch = 25

// maxOutputLines bounds the lines indexed per recording; a session that
// prints more (a log followed for an hour) is searchable in its first ones,
// the recording keeping all of it.
const maxOutputLines = 5000

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
	output := x.IndexOutput != nil && x.IndexOutput()
	if !output {
		if err := x.Repo.forgetAllOutput(ctx); err != nil {
			return 0, err
		}
	}
	todo, err := x.Repo.unindexedCasts(ctx, indexBatch, output)
	if err != nil {
		return 0, err
	}
	for _, u := range todo {
		// One read for both: a new recording is read once.
		lines := 0
		if output && !u.output {
			lines = maxOutputLines
		}
		var (
			markers []recording.Marker
			printed []recording.OutputLine
		)
		rc, err := x.Storage.Open(ctx, u.uri)
		if err == nil {
			markers, printed, _, err = recording.Index(rc, lines)
			_ = rc.Close()
		}
		if err != nil {
			x.Log.Warn("command index: recording unreadable; indexed as empty", "recording", u.id, "err", err)
			markers, printed = nil, nil
		}
		if !u.commands {
			if err := x.Repo.IndexCommands(ctx, u.id, markers); err != nil {
				return 0, err
			}
		}
		if lines > 0 {
			if err := x.Repo.IndexOutput(ctx, u.id, printed); err != nil {
				return 0, err
			}
		}
	}
	return len(todo), nil
}
