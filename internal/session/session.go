// SPDX-License-Identifier: Apache-2.0

// Package session persists access sessions (a person connected to a target)
// and their recordings. The gateway writes here; the user, admin and auditor
// APIs read from here.
package session

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
)

// EndReason values match the access_sessions.end_reason column.
const (
	EndUserExit        = "user_exit"
	EndIdleTimeout     = "idle_timeout"
	EndMaxDuration     = "max_duration"
	EndAdminTerminated = "admin_terminated"
	EndTargetLost      = "target_lost"
	EndFailover        = "failover"
	EndError           = "error"
	EndPolicyRevoked   = "policy_revoked"
	EndGatewayRestart  = "gateway_restart"
	// EndTrustLost: the target's pinned host key or certificate changed
	// while the session ran (ADR 0013).
	EndTrustLost = "trust_lost"
	// EndNoWatcher: a session held for a second person (four eyes, ADR
	// 0042) that nobody watched in time. No longer given: four eyes was
	// removed in 1.16.0; kept for the sessions 1.15.0 ended so.
	EndNoWatcher = "no_watcher"
)

// Session is one connection from a user to a target.
type Session struct {
	ID       string `json:"id"`
	UserID   string `json:"user_id"`
	Username string `json:"username,omitempty"`
	// UserDeleted marks a session whose account no longer exists; Username is
	// then the name it had when the session started (ADR 0046).
	UserDeleted bool   `json:"user_deleted,omitempty"`
	TargetName  string `json:"target_name,omitempty"`
	// ASGName and InstanceID label a session on an autoscaling instance the
	// way TargetName labels one on a static target: the group's name and the
	// cloud instance id. Resolved at read time from rows that outlive deletion
	// (ADR 0019), so history never degrades to bare ids.
	ASGName       string     `json:"asg_name,omitempty"`
	InstanceID    string     `json:"instance_id,omitempty"`
	PolicyID      string     `json:"policy_id,omitempty"`
	TargetID      string     `json:"target_id,omitempty"`
	ASGID         string     `json:"asg_id,omitempty"`
	ASGInstanceID string     `json:"asg_instance_id,omitempty"`
	Protocol      string     `json:"protocol"`
	CredentialID  string     `json:"credential_id,omitempty"`
	ClientIP      string     `json:"client_ip"`
	UserAgent     string     `json:"user_agent,omitempty"`
	StartedAt     time.Time  `json:"started_at"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
	EndReason     string     `json:"end_reason,omitempty"`
	// EndDetail is what was said about the end: the gateway's sentence to
	// the person, or the target's side's words (Q7). Empty for a plain exit.
	EndDetail             string `json:"end_detail,omitempty"`
	FailoverFromSessionID string `json:"failover_from_session_id,omitempty"`
	RecordingID           string `json:"recording_id,omitempty"`
	// RecordingPurged says retention has deleted the recording's file; the
	// row stays so its events resolve. RecordingKeptUntil is when retention
	// deletes it by age: its own date, else the global age from when it
	// finished; absent with no age limit (2026-11-03 live audit, Q10). The
	// size cap can still take it sooner. Reviewers only; set by WithRetention.
	RecordingPurged    bool       `json:"recording_purged,omitempty"`
	RecordingKeptUntil *time.Time `json:"recording_kept_until,omitempty"`

	recOwnUntil, recFinished *time.Time
}

// WithRetention fills RecordingKeptUntil from the global policy p, by the
// rule the retention sweeper applies (selectForPurge).
func (s *Session) WithRetention(p RetentionPolicy) {
	s.RecordingKeptUntil = keptUntil(s.recOwnUntil, s.recFinished, s.RecordingPurged, p)
}

// HideRecording clears everything about the session's recording, for a reader
// who may see their own sessions but not their recordings (ADR 0006).
func (s *Session) HideRecording() {
	s.RecordingID, s.RecordingPurged, s.RecordingKeptUntil = "", false, nil
}

// keptUntil is when retention deletes a recording by age, or nil when it is
// gone already, still being written, or kept without an age limit.
func keptUntil(own, finished *time.Time, purged bool, p RetentionPolicy) *time.Time {
	switch {
	case purged || finished == nil:
		return nil
	case own != nil:
		return own
	case p.MaxAgeDays > 0:
		t := finished.AddDate(0, 0, p.MaxAgeDays)
		return &t
	}
	return nil
}

// Recording is the stored capture of a session.
type Recording struct {
	ID             string     `json:"id"`
	SessionID      string     `json:"session_id"`
	Format         string     `json:"format"` // asciicast | guac
	StorageURI     string     `json:"-"`
	SizeBytes      int64      `json:"size_bytes"`
	SHA256         string     `json:"sha256,omitempty"`
	StartedAt      time.Time  `json:"started_at"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	RetentionUntil *time.Time `json:"retention_until,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	// PurgedAt is set once retention has deleted the blob; the metadata row
	// stays so audit events that reference this recording still resolve.
	PurgedAt *time.Time `json:"purged_at,omitempty"`
}

// ErrNotFound is returned for unknown ids.
var ErrNotFound = errors.New("session: not found")

// ErrUnknownUser is returned when a session or a recording view names an
// account that does not exist.
var ErrUnknownUser = errors.New("session: unknown user")

// Repo persists sessions and recordings.
type Repo struct {
	db *store.DB
}

// NewRepo returns a repository over db.
func NewRepo(db *store.DB) *Repo { return &Repo{db: db} }

// Start inserts a new open session. ID and StartedAt are set.
func (r *Repo) Start(ctx context.Context, s *Session) error {
	s.ID = store.NewID()
	s.StartedAt = time.Now().UTC()
	username, display, err := r.identity(ctx, s.UserID)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO access_sessions
		(id, user_id, user_username, user_display_name, policy_id, target_id, asg_id, asg_instance_id, protocol, credential_id, client_ip, user_agent, started_at, failover_from_session_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		s.ID, s.UserID, username, display, nullStr(s.PolicyID), nullStr(s.TargetID), nullStr(s.ASGID), nullStr(s.ASGInstanceID), s.Protocol,
		nullStr(s.CredentialID), s.ClientIP, s.UserAgent, store.TimeArg(s.StartedAt), nullStr(s.FailoverFromSessionID))
	return err
}

// identity returns the username and display name a row is written with, so
// the row still says who the person was after the account is deleted (ADR
// 0046). Nothing but this lookup stops a row from naming an account that does
// not exist: there is no foreign key.
func (r *Repo) identity(ctx context.Context, userID string) (username, display string, err error) {
	err = r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT username, display_name FROM users WHERE id = ?`), userID).Scan(&username, &display)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrUnknownUser
	}
	return username, display, err
}

// End closes a session with a reason. Ending twice is a no-op.
func (r *Repo) End(ctx context.Context, id, reason string) error {
	return r.EndWithDetail(ctx, id, reason, "")
}

// maxEndDetail bounds the words kept with a session's end: a guacd message
// or the gateway's own sentence, never a dump.
const maxEndDetail = 500

// EndWithDetail closes a session with a reason and, when there is one, what
// was said about it: the sentence the person was shown, or what the target's
// side said (2026-11-03 live audit, Q7). Ending twice is a no-op.
func (r *Repo) EndWithDetail(ctx context.Context, id, reason, detail string) error {
	detail = strings.TrimSpace(detail)
	if len(detail) > maxEndDetail {
		detail = strings.ToValidUTF8(detail[:maxEndDetail], "") + "…"
	}
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE access_sessions SET ended_at = ?, end_reason = ?, end_detail = ? WHERE id = ? AND ended_at IS NULL`),
		store.TimeArg(time.Now()), reason, nullStr(detail), id)
	return err
}

// DiscardRecording deletes nothing itself: it marks a recording whose
// session never drew a frame (Q6), once its file is deleted, as purged and
// discarded at when. Lists leave a discarded recording out; its row stays so
// the events that name it resolve.
func (r *Repo) DiscardRecording(ctx context.Context, id string, when time.Time) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE recordings SET discarded_at = ?, purged_at = ? WHERE id = ? AND purged_at IS NULL`),
		store.TimeArg(when), store.TimeArg(when), id)
	return err
}

// Counts are the session numbers the dashboards show (ADR 0029). Open is the
// database's view, the same number the Sessions pages list, so the tile and
// the page it links to can never disagree.
type Counts struct {
	Open         int `json:"open"`
	StartedSince int `json:"started_24h"`
}

// Count returns how many sessions are open and how many started at or after
// since. Two queries, one after another: the single-connection SQLite setup
// forbids overlapping them.
func (r *Repo) Count(ctx context.Context, since time.Time) (Counts, error) {
	var c Counts
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_sessions WHERE ended_at IS NULL`).Scan(&c.Open); err != nil {
		return Counts{}, err
	}
	err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT COUNT(*) FROM access_sessions WHERE started_at >= ?`), store.TimeArg(since)).Scan(&c.StartedSince)
	return c, err
}

// StartedPer counts the sessions started in each range between consecutive
// bounds, [bounds[i], bounds[i+1]), one query after another (2026-10-31,
// the dashboard's trends).
func (r *Repo) StartedPer(ctx context.Context, bounds []time.Time) ([]int, error) {
	out := make([]int, 0, max(len(bounds)-1, 0))
	for i := 0; i+1 < len(bounds); i++ {
		var n int
		if err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT COUNT(*) FROM access_sessions WHERE started_at >= ? AND started_at < ?`),
			store.TimeArg(bounds[i]), store.TimeArg(bounds[i+1])).Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

// Get returns a session.
func (r *Repo) Get(ctx context.Context, id string) (*Session, error) {
	row := r.db.QueryRowContext(ctx, r.db.Rebind(selectSessions+` WHERE s.id = ?`), id)
	return scanSession(row)
}

// Filter narrows List.
type Filter struct {
	UserID string
	// Username narrows to one account by name, which is what an admin has in
	// front of them; matched case-insensitively (usernames are stored lower).
	Username string
	TargetID string
	OpenOnly bool
	// From narrows to sessions started at or after it, as Count's
	// StartedSince counts them; zero means any time.
	From  time.Time
	Limit int
	// Cursor is the started_at of the last row seen, as List returns it. Any
	// RFC 3339 form is read as a time and compared in the stored form, so a
	// cursor from before migration 0030 pages the same way.
	Cursor string
}

// ErrBadCursor is returned by List for a cursor that is not an RFC 3339 time.
var ErrBadCursor = errors.New("session: the cursor is not a time")

// List returns sessions newest first.
func (r *Repo) List(ctx context.Context, f Filter) ([]*Session, string, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	q := selectSessions + ` WHERE 1=1`
	var args []any
	if f.UserID != "" {
		q += ` AND s.user_id = ?`
		args = append(args, f.UserID)
	}
	// A part of a name finds it, in any case (2026-11-04: the whole name was
	// needed); the list stays newest first, not ranked.
	if s, ok := store.NewSearch(f.Username, "COALESCE(u.username, s.user_username)"); ok {
		q += ` AND ` + s.Where
		args = append(args, s.WhereArgs...)
	}
	if f.TargetID != "" {
		q += ` AND s.target_id = ?`
		args = append(args, f.TargetID)
	}
	if f.OpenOnly {
		q += ` AND s.ended_at IS NULL`
	}
	if !f.From.IsZero() {
		q += ` AND s.started_at >= ?`
		args = append(args, store.TimeArg(f.From))
	}
	if f.Cursor != "" {
		at, err := time.Parse(time.RFC3339Nano, f.Cursor)
		if err != nil {
			return nil, "", ErrBadCursor
		}
		q += ` AND s.started_at < ?`
		args = append(args, store.TimeArg(at))
	}
	q += ` ORDER BY s.started_at DESC LIMIT ?`
	args = append(args, f.Limit+1)
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(q), args...)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()
	var out []*Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > f.Limit {
		out = out[:f.Limit]
		next = store.TimeArg(out[len(out)-1].StartedAt)
	}
	if out == nil {
		out = []*Session{}
	}
	return out, next, nil
}

// CreateRecording registers a recording for a session before bytes flow.
func (r *Repo) CreateRecording(ctx context.Context, rec *Recording) error {
	rec.ID = store.NewID()
	now := time.Now().UTC()
	rec.CreatedAt, rec.StartedAt = now, now
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO recordings (id, session_id, format, storage_uri, size_bytes, started_at, retention_until, created_at)
		VALUES (?, ?, ?, ?, 0, ?, ?, ?)`),
		rec.ID, rec.SessionID, rec.Format, rec.StorageURI, store.TimeArg(now), store.NullTime{Time: derefTime(rec.RetentionUntil), Valid: rec.RetentionUntil != nil}, store.TimeArg(now))
	return err
}

// FinishRecording records the final size and digest.
func (r *Repo) FinishRecording(ctx context.Context, id string, size int64, sha256 string) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE recordings SET size_bytes = ?, sha256 = ?, finished_at = ? WHERE id = ?`),
		size, sha256, store.TimeArg(time.Now()), id)
	return err
}

// RecordingTotals counts the recordings kept and the bytes they take, for
// the dashboard (2026-10-31): finished ones that retention has not purged,
// wherever they are stored. A recording still being written counts once it
// ends.
func (r *Repo) RecordingTotals(ctx context.Context) (count, bytes int64, err error) {
	err = r.db.QueryRowContext(ctx, `SELECT COUNT(*), CAST(COALESCE(SUM(size_bytes), 0) AS BIGINT) FROM recordings
		WHERE finished_at IS NOT NULL AND purged_at IS NULL`).Scan(&count, &bytes)
	return count, bytes, err
}

// GetRecording returns one recording.
func (r *Repo) GetRecording(ctx context.Context, id string) (*Recording, error) {
	var (
		rec                                        Recording
		sha                                        sql.NullString
		started, finished, retain, created, purged store.NullTime
	)
	err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT id, session_id, format, storage_uri, size_bytes, sha256, started_at, finished_at, retention_until, created_at, purged_at
		FROM recordings WHERE id = ?`), id).Scan(&rec.ID, &rec.SessionID, &rec.Format, &rec.StorageURI, &rec.SizeBytes, &sha, &started, &finished, &retain, &created, &purged)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	rec.SHA256 = sha.String
	rec.StartedAt, rec.FinishedAt, rec.RetentionUntil, rec.CreatedAt, rec.PurgedAt = started.Time, finished.Ptr(), retain.Ptr(), created.Time, purged.Ptr()
	return &rec, nil
}

// RecordView logs that a person viewed a recording (ADR 0006).
func (r *Repo) RecordView(ctx context.Context, recordingID, userID, ip string) error {
	username, display, err := r.identity(ctx, userID)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO recording_views (id, recording_id, user_id, user_username, user_display_name, ip, viewed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`),
		store.NewID(), recordingID, userID, username, display, ip, store.TimeArg(time.Now()))
	return err
}

// selectSessions joins the names a reader wants next to every session. The
// joins deliberately ignore deleted_at: a retired target or group still
// labels its past sessions (ADR 0019).
const selectSessions = `SELECT s.id, s.user_id, s.policy_id, s.target_id, s.asg_id, s.asg_instance_id, s.protocol, s.credential_id,
	s.client_ip, s.user_agent, s.started_at, s.ended_at, s.end_reason, s.failover_from_session_id, rec.id, COALESCE(u.username, s.user_username), u.id, t.name,
	g.name, ai.instance_id, rec.purged_at, rec.retention_until, rec.finished_at, s.end_detail
	FROM access_sessions s
	LEFT JOIN recordings rec ON rec.session_id = s.id AND rec.discarded_at IS NULL
	LEFT JOIN users u ON u.id = s.user_id
	LEFT JOIN targets t ON t.id = s.target_id
	LEFT JOIN autoscaling_groups g ON g.id = s.asg_id
	LEFT JOIN asg_instances ai ON ai.id = s.asg_instance_id`

func scanSession(sc store.Scanner) (*Session, error) {
	var (
		s                                                                                                     Session
		policy, target, asg, inst, cred, reason, failover, recID, username, liveID, tname, gname, iid, detail sql.NullString
		started, ended, purged, recUntil, recFinished                                                         store.NullTime
	)
	err := sc.Scan(&s.ID, &s.UserID, &policy, &target, &asg, &inst, &s.Protocol, &cred, &s.ClientIP, &s.UserAgent,
		&started, &ended, &reason, &failover, &recID, &username, &liveID, &tname, &gname, &iid, &purged, &recUntil, &recFinished, &detail)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	s.PolicyID, s.TargetID, s.ASGID, s.ASGInstanceID, s.CredentialID = policy.String, target.String, asg.String, inst.String, cred.String
	s.EndReason, s.FailoverFromSessionID, s.RecordingID = reason.String, failover.String, recID.String
	s.Username, s.TargetName, s.ASGName, s.InstanceID = username.String, tname.String, gname.String, iid.String
	s.UserDeleted = !liveID.Valid
	s.StartedAt, s.EndedAt = started.Time, ended.Ptr()
	s.RecordingPurged, s.recOwnUntil, s.recFinished = purged.Valid, recUntil.Ptr(), recFinished.Ptr()
	s.EndDetail = detail.String
	return &s, nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// ListRecordingsByURIPrefix pages, by id, over finished, unpurged recordings
// whose storage URI starts with prefix (for example "file://"). The move to
// S3 walks the local ones with it.
func (r *Repo) ListRecordingsByURIPrefix(ctx context.Context, prefix, afterID string, limit int) ([]*Recording, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT id, session_id, format, storage_uri, size_bytes, sha256, started_at, finished_at, retention_until, created_at, purged_at
		FROM recordings WHERE storage_uri LIKE ? ESCAPE '\' AND finished_at IS NOT NULL AND purged_at IS NULL AND id > ? ORDER BY id LIMIT ?`),
		strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(prefix)+"%", afterID, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Recording
	for rows.Next() {
		var (
			rec                                        Recording
			sha                                        sql.NullString
			started, finished, retain, created, purged store.NullTime
		)
		if err := rows.Scan(&rec.ID, &rec.SessionID, &rec.Format, &rec.StorageURI, &rec.SizeBytes, &sha, &started, &finished, &retain, &created, &purged); err != nil {
			return nil, err
		}
		rec.SHA256 = sha.String
		rec.StartedAt, rec.FinishedAt, rec.RetentionUntil, rec.CreatedAt, rec.PurgedAt = started.Time, finished.Ptr(), retain.Ptr(), created.Time, purged.Ptr()
		out = append(out, &rec)
	}
	return out, rows.Err()
}

// UpdateRecordingURI points a recording at its new blob. It refuses when
// the row no longer holds the URI the caller moved from, so a concurrent
// purge is not undone.
func (r *Repo) UpdateRecordingURI(ctx context.Context, id, from, to string) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE recordings SET storage_uri = ? WHERE id = ? AND storage_uri = ? AND purged_at IS NULL`), to, id, from)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountRecordingsByStore counts unpurged recordings per store: "local" for
// the directory, "s3://bucket" for each bucket seen.
func (r *Repo) CountRecordingsByStore(ctx context.Context) (map[string]int, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT storage_uri FROM recordings WHERE purged_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var uri string
		if err := rows.Scan(&uri); err != nil {
			return nil, err
		}
		key := "local"
		if rest, ok := strings.CutPrefix(uri, "s3://"); ok {
			bucket, _, _ := strings.Cut(rest, "/")
			key = "s3://" + bucket
		}
		out[key]++
	}
	return out, rows.Err()
}
