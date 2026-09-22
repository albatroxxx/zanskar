// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
)

// advisoryLockID serialises writers across gateway processes on PostgreSQL.
// The value is arbitrary but must never change: 'ZANSK' in ASCII.
const advisoryLockID int64 = 0x5a414e534b

const (
	defaultListLimit = 50
	maxListLimit     = 500
	verifyBatchSize  = 1000
)

// Log persists events to audit_events and keeps the hash chain unbroken.
type Log struct {
	db *store.DB
	mu sync.Mutex
}

// NewLog returns a Log backed by db.
func NewLog(db *store.DB) *Log {
	return &Log{db: db}
}

// Actor identifies who performed an action. Handlers build one from the
// authenticated session and the client address.
type Actor struct {
	UserID string
	IP     string
}

// Event builds an Event for this actor. details may be nil, a json.RawMessage,
// or any value that marshals to a JSON object.
func (a Actor) Event(action, objectType, objectID string, outcome Outcome, details any) Event {
	e := Event{
		ActorUserID: a.UserID,
		ActorIP:     a.IP,
		Action:      action,
		ObjectType:  objectType,
		ObjectID:    objectID,
		Outcome:     outcome,
	}
	switch d := details.(type) {
	case nil:
	case json.RawMessage:
		e.Details = d
	case []byte:
		e.Details = json.RawMessage(d)
	default:
		if b, err := json.Marshal(d); err == nil {
			e.Details = b
		}
	}
	return e
}

// Record links e to the current chain head and inserts it. It returns the
// stored event including its ID. Writers are serialised in-process with a
// mutex and, on PostgreSQL, across processes with a transaction-scoped
// advisory lock, so the chain can never fork.
func (l *Log) Record(ctx context.Context, e Event) (Event, error) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	} else {
		e.Timestamp = e.Timestamp.UTC()
	}
	// PostgreSQL's TIMESTAMPTZ keeps only microseconds, so a nanosecond-precision
	// timestamp read back after insert differs from the one that was hashed and
	// the chain fails verification. Truncate before hashing so the hash covers
	// exactly what the column will return. (SQLite stores full-precision text and
	// is unaffected, but truncating on both keeps the chain portable.)
	e.Timestamp = e.Timestamp.Truncate(time.Microsecond)
	if e.Outcome == "" {
		return Event{}, errors.New("audit: outcome is required")
	}
	if e.Action == "" {
		return Event{}, errors.New("audit: action is required")
	}
	if len(e.Details) == 0 {
		e.Details = json.RawMessage("{}")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return Event{}, fmt.Errorf("audit: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if l.db.Driver == config.DriverPostgres {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockID); err != nil {
			return Event{}, fmt.Errorf("audit: advisory lock: %w", err)
		}
	}

	var prev string
	err = tx.QueryRowContext(ctx, `SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Event{}, fmt.Errorf("audit: read head: %w", err)
	}
	if err := Link(&e, prev); err != nil {
		return Event{}, err
	}

	const q = `INSERT INTO audit_events
		(ts, actor_user_id, actor_ip, action, object_type, object_id, outcome, details, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	args := []any{
		l.tsArg(e.Timestamp), nullIfEmpty(e.ActorUserID), e.ActorIP, e.Action, e.ObjectType, e.ObjectID,
		string(e.Outcome), string(e.Details), e.PrevHash, e.Hash,
	}
	if l.db.Driver == config.DriverPostgres {
		if err := tx.QueryRowContext(ctx, l.db.Rebind(q+` RETURNING id`), args...).Scan(&e.ID); err != nil {
			return Event{}, fmt.Errorf("audit: insert: %w", err)
		}
	} else {
		res, err := tx.ExecContext(ctx, l.db.Rebind(q), args...)
		if err != nil {
			return Event{}, fmt.Errorf("audit: insert: %w", err)
		}
		if e.ID, err = res.LastInsertId(); err != nil {
			return Event{}, fmt.Errorf("audit: insert id: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Event{}, fmt.Errorf("audit: commit: %w", err)
	}
	return e, nil
}

// Filter narrows List. Zero values are ignored. Cursor is the value returned
// by a previous List call.
type Filter struct {
	ActorUserID string
	Action      string
	ObjectType  string
	ObjectID    string
	From, To    time.Time
	// Exclude drops routine events from a listing without touching the log.
	// Each entry is an action ("audit.read") or action:outcome
	// ("session.connect:success"), so a reader can hide the successful
	// ticket issue that precedes every session while still seeing refusals.
	Exclude []string
	Cursor  string
	Limit   int
}

// List returns events newest first. The second return value is the cursor for
// the next page, empty when there are no more rows.
func (l *Log) List(ctx context.Context, f Filter) ([]Event, string, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = defaultListLimit
	}
	if limit > maxListLimit {
		limit = maxListLimit
	}

	var where []string
	var args []any
	add := func(clause string, v any) {
		where = append(where, clause)
		args = append(args, v)
	}
	if f.ActorUserID != "" {
		add("actor_user_id = ?", f.ActorUserID)
	}
	if f.Action != "" {
		add("action = ?", f.Action)
	}
	if f.ObjectType != "" {
		add("object_type = ?", f.ObjectType)
	}
	if f.ObjectID != "" {
		add("object_id = ?", f.ObjectID)
	}
	for _, ex := range f.Exclude {
		if action, outcome, ok := strings.Cut(ex, ":"); ok {
			where = append(where, "NOT (action = ? AND outcome = ?)")
			args = append(args, action, outcome)
		} else {
			add("action <> ?", ex)
		}
	}
	if !f.From.IsZero() {
		add("ts >= ?", l.tsArg(f.From.UTC()))
	}
	if !f.To.IsZero() {
		add("ts < ?", l.tsArg(f.To.UTC()))
	}
	if f.Cursor != "" {
		id, err := strconv.ParseInt(f.Cursor, 10, 64)
		if err != nil {
			return nil, "", fmt.Errorf("audit: invalid cursor")
		}
		add("id < ?", id)
	}

	q := selectColumns
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit+1)

	rows, err := l.db.QueryContext(ctx, l.db.Rebind(q), args...)
	if err != nil {
		return nil, "", fmt.Errorf("audit: list: %w", err)
	}
	defer func() { _ = rows.Close() }()

	events := make([]Event, 0, limit)
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, "", err
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("audit: list: %w", err)
	}

	next := ""
	if len(events) > limit {
		events = events[:limit]
		next = strconv.FormatInt(events[len(events)-1].ID, 10)
	}
	return events, next, nil
}

// VerifyResult reports the outcome of a full chain walk.
type VerifyResult struct {
	Checked  int64
	LastID   int64
	LastHash string
	Broken   *VerifyError // nil when the chain is intact
}

// Verify walks the whole log in id order and checks every link and hash. It
// reads in batches so memory stays flat regardless of log size. A broken chain
// is reported in the result, not as an error; errors are for I/O failures.
func (l *Log) Verify(ctx context.Context) (VerifyResult, error) {
	res := VerifyResult{LastHash: GenesisHash}
	prev := GenesisHash
	var afterID int64
	q := l.db.Rebind(selectColumns + " WHERE id > ? ORDER BY id ASC LIMIT ?")

	for {
		batch, err := l.fetchBatch(ctx, q, afterID)
		if err != nil {
			return res, err
		}
		if len(batch) == 0 {
			return res, nil
		}
		for _, e := range batch {
			idx := int(res.Checked)
			if e.PrevHash != prev {
				res.Broken = &VerifyError{Index: idx, ID: e.ID, Reason: "prev_hash does not match previous event"}
				return res, nil
			}
			want, err := ComputeHash(e)
			if err != nil {
				res.Broken = &VerifyError{Index: idx, ID: e.ID, Reason: err.Error()}
				return res, nil
			}
			if want != e.Hash {
				res.Broken = &VerifyError{Index: idx, ID: e.ID, Reason: "hash does not match content"}
				return res, nil
			}
			prev = e.Hash
			res.Checked++
			res.LastID = e.ID
			res.LastHash = e.Hash
			afterID = e.ID
		}
		if len(batch) < verifyBatchSize {
			return res, nil
		}
	}
}

func (l *Log) fetchBatch(ctx context.Context, q string, afterID int64) ([]Event, error) {
	rows, err := l.db.QueryContext(ctx, q, afterID, verifyBatchSize)
	if err != nil {
		return nil, fmt.Errorf("audit: verify: %w", err)
	}
	defer func() { _ = rows.Close() }()
	batch := make([]Event, 0, verifyBatchSize)
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		batch = append(batch, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: verify: %w", err)
	}
	return batch, nil
}

// maxFacetValues bounds a facet list. The vocabularies are small by design; the
// cap only stops a pathological log from building an unusable filter.
const maxFacetValues = 200

// Facets are the values a reviewer can pick from when filtering. Only values the
// log actually contains are listed, so the filter never offers a choice that
// would return nothing.
type Facets struct {
	Actions     []string `json:"actions"`
	ObjectTypes []string `json:"object_types"`
}

// Facets reads the distinct action and object_type values in the log.
func (l *Log) Facets(ctx context.Context) (Facets, error) {
	var f Facets
	var err error
	if f.Actions, err = l.distinct(ctx, "action"); err != nil {
		return Facets{}, err
	}
	if f.ObjectTypes, err = l.distinct(ctx, "object_type"); err != nil {
		return Facets{}, err
	}
	return f, nil
}

// distinct lists the values held in one column. The column is named by a
// caller-supplied literal and never by request input, so interpolating it into
// the statement cannot be turned into an injection. Each result set is drained
// before returning, because SQLite runs on a single connection.
func (l *Log) distinct(ctx context.Context, column string) ([]string, error) {
	q := `SELECT DISTINCT ` + column + ` FROM audit_events WHERE ` + column + ` IS NOT NULL AND ` + column + ` <> '' ORDER BY 1`
	rows, err := l.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("audit: facets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]string, 0, 32)
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("audit: facets: %w", err)
		}
		if len(out) >= maxFacetValues {
			break
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: facets: %w", err)
	}
	return out, nil
}

// ResealResult reports what Reseal changed.
type ResealResult struct {
	Scanned   int64
	Rewritten int64
	// FirstID and LastID bound the rows whose stored hash was replaced. Both are
	// zero when nothing needed rewriting.
	FirstID int64
	LastID  int64
	Head    string
}

// Reseal relinks and rehashes the log, rewriting every row whose stored hash
// does not match its content.
//
// This is a last-resort recovery, not maintenance. When a chain is broken by a
// hash-computation bug the original hashes cannot be reproduced, because the
// input they covered is gone: a pre-fix build hashed nanosecond timestamps that
// PostgreSQL's TIMESTAMPTZ then truncated to microseconds, so those rows can
// never satisfy Verify again. Reseal makes the log verifiable at a real cost —
// it permanently destroys the chain's evidence that the rewritten rows were not
// altered, because a reseal and a tampering are indistinguishable after the
// fact. Run it only when the break is understood, and record why: the CLI
// writes an audit.reseal event describing the rewrite.
//
// Rewriting starts at the first mismatch and necessarily continues to the head,
// because each hash covers the previous row's hash.
func (l *Log) Reseal(ctx context.Context) (ResealResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var res ResealResult
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("audit: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if l.db.Driver == config.DriverPostgres {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockID); err != nil {
			return res, fmt.Errorf("audit: advisory lock: %w", err)
		}
	}

	selQ := l.db.Rebind(selectColumns + " WHERE id > ? ORDER BY id ASC LIMIT ?")
	updQ := l.db.Rebind(`UPDATE audit_events SET prev_hash = ?, hash = ? WHERE id = ?`)

	prev := GenesisHash
	var afterID int64
	for {
		// Drain each batch before issuing updates: SQLite runs on one connection
		// and deadlocks if a second statement starts while a cursor is open.
		batch, err := fetchBatchTx(ctx, tx, selQ, afterID)
		if err != nil {
			return res, err
		}
		if len(batch) == 0 {
			break
		}
		for _, e := range batch {
			storedHash, storedPrev := e.Hash, e.PrevHash
			e.PrevHash = prev
			want, err := ComputeHash(e)
			if err != nil {
				return res, fmt.Errorf("audit: reseal event %d: %w", e.ID, err)
			}
			if want != storedHash || prev != storedPrev {
				if _, err := tx.ExecContext(ctx, updQ, prev, want, e.ID); err != nil {
					return res, fmt.Errorf("audit: reseal event %d: %w", e.ID, err)
				}
				res.Rewritten++
				if res.FirstID == 0 {
					res.FirstID = e.ID
				}
				res.LastID = e.ID
			}
			prev = want
			res.Scanned++
			afterID = e.ID
		}
		if len(batch) < verifyBatchSize {
			break
		}
	}
	res.Head = prev
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("audit: commit: %w", err)
	}
	return res, nil
}

// fetchBatchTx is fetchBatch bound to a transaction.
func fetchBatchTx(ctx context.Context, tx *sql.Tx, q string, afterID int64) ([]Event, error) {
	rows, err := tx.QueryContext(ctx, q, afterID, verifyBatchSize)
	if err != nil {
		return nil, fmt.Errorf("audit: reseal: %w", err)
	}
	defer func() { _ = rows.Close() }()
	batch := make([]Event, 0, verifyBatchSize)
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		batch = append(batch, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: reseal: %w", err)
	}
	return batch, nil
}

// ---- row mapping

const selectColumns = `SELECT id, ts, actor_user_id, actor_ip, action, object_type, object_id, outcome, details, prev_hash, hash FROM audit_events`

// tsArg formats a timestamp for the driver: RFC 3339 nano text on SQLite,
// a native timestamptz on PostgreSQL.
func (l *Log) tsArg(t time.Time) any {
	if l.db.Driver == config.DriverPostgres {
		return t.UTC()
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// tsScan accepts whatever the driver hands back for a timestamp column.
type tsScan struct{ t time.Time }

func (s *tsScan) Scan(v any) error {
	switch x := v.(type) {
	case time.Time:
		s.t = x.UTC()
	case string:
		t, err := time.Parse(time.RFC3339Nano, x)
		if err != nil {
			return fmt.Errorf("audit: bad timestamp %q: %w", x, err)
		}
		s.t = t.UTC()
	case []byte:
		return s.Scan(string(x))
	case nil:
		s.t = time.Time{}
	default:
		return fmt.Errorf("audit: unsupported timestamp type %T", v)
	}
	return nil
}

func scanEvent(rows *sql.Rows) (Event, error) {
	var (
		e       Event
		ts      tsScan
		actor   sql.NullString
		details []byte
		outcome string
	)
	if err := rows.Scan(&e.ID, &ts, &actor, &e.ActorIP, &e.Action, &e.ObjectType, &e.ObjectID, &outcome, &details, &e.PrevHash, &e.Hash); err != nil {
		return Event{}, fmt.Errorf("audit: scan: %w", err)
	}
	e.Timestamp = ts.t
	e.ActorUserID = actor.String
	e.Outcome = Outcome(outcome)
	e.Details = json.RawMessage(details)
	return e, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ListAfter returns up to limit events with id > afterID in ascending order.
// It is the feed for exporters, which must see every event in chain order.
func (l *Log) ListAfter(ctx context.Context, afterID int64, limit int) ([]Event, error) {
	if limit <= 0 || limit > maxListLimit {
		limit = maxListLimit
	}
	rows, err := l.db.QueryContext(ctx, l.db.Rebind(selectColumns+" WHERE id > ? ORDER BY id ASC LIMIT "+strconv.Itoa(limit)), afterID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Event
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// ExportCheckpoint returns the last exported id for a sink (0 when none).
func (l *Log) ExportCheckpoint(ctx context.Context, sink string) (int64, error) {
	var id int64
	err := l.db.QueryRowContext(ctx, l.db.Rebind(`SELECT last_id FROM audit_export_state WHERE sink = ?`), sink).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// SaveExportCheckpoint records the last exported id for a sink.
func (l *Log) SaveExportCheckpoint(ctx context.Context, sink string, lastID int64) error {
	now := store.TimeArg(time.Now())
	res, err := l.db.ExecContext(ctx, l.db.Rebind(`UPDATE audit_export_state SET last_id = ?, updated_at = ? WHERE sink = ?`), lastID, now, sink)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	_, err = l.db.ExecContext(ctx, l.db.Rebind(`INSERT INTO audit_export_state (sink, last_id, updated_at) VALUES (?, ?, ?)`), sink, lastID, now)
	return err
}
