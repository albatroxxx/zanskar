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
	Cursor      string
	Limit       int
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
