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
		// A nil map or pointer arrives typed, so it is not the nil case
		// above, and marshals to null, which Record refuses: the event was
		// lost (user.mfa.confirm at every sign-in that enrolled an
		// authenticator, until 2026-10-30). No details is what it means.
		if b, err := json.Marshal(d); err == nil && string(b) != "null" {
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
	// exactly what the column will return. (SQLite stores the same microseconds,
	// as fixed-width text: store.TimeArg.)
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
		if err := tx.QueryRowContext(ctx, l.db.Rebind(q+` RETURNING id`), args...).Scan(&e.ID); err != nil { // #nosec G701 -- constant statement, bound args
			return Event{}, fmt.Errorf("audit: insert: %w", err)
		}
	} else {
		res, err := tx.ExecContext(ctx, l.db.Rebind(q), args...) // #nosec G701 -- constant statement, bound args
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
	// Outcome narrows to successes or failures; empty means both. The
	// dashboards' failure counts open the list with it.
	Outcome    Outcome
	ObjectType string
	ObjectID   string
	From, To   time.Time
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
	if f.Outcome != "" {
		add("outcome = ?", string(f.Outcome))
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

// VerifyResult reports the outcome of a full chain walk and of the checks
// against the anchors and the id sequence (ADR 0008).
type VerifyResult struct {
	Checked  int64
	LastID   int64
	LastHash string
	Broken   *VerifyError // nil when the chain is intact

	// Anchors is how many anchors were checked, stored and supplied.
	Anchors int
	// LastAnchor is the matching anchor that names the newest event: its
	// signature verifies and its event is still in the log with the hash it
	// signed. Nil when no anchor matches.
	LastAnchor *Anchor
	// Problems are what the anchor and sequence checks found. Each is
	// evidence that the log was truncated or edited, or that an anchor was
	// not written by this gateway.
	Problems []string
	// Warnings may be innocent and do not fail the check: on PostgreSQL, an
	// id sequence ahead of the newest event.
	Warnings []string
}

// Intact reports whether the chain verified and no anchor or sequence check
// found a problem.
func (r VerifyResult) Intact() bool {
	return r.Broken == nil && len(r.Problems) == 0
}

// maxAnchorReports bounds how many anchor problems are listed one by one;
// the rest are counted in a final entry.
const maxAnchorReports = 20

// Verify walks the whole log in id order and checks every link and hash. It
// reads in batches so memory stays flat regardless of log size. It then
// checks every stored anchor, and each anchor supplied from outside the
// database, against the log: the signature under key, and that the event it
// names is still there with the hash it signed. Last it compares the id
// sequence with the newest event, which notices the newest rows being deleted
// before any anchor covers them. A broken chain or a problem is reported in
// the result, not as an error; errors are for I/O failures and a missing key.
func (l *Log) Verify(ctx context.Context, key []byte, kept ...Anchor) (VerifyResult, error) {
	if len(key) == 0 {
		return VerifyResult{LastHash: GenesisHash}, ErrNoAnchorKey
	}
	res, err := l.walk(ctx)
	if err != nil {
		return res, err
	}
	if err := l.checkAnchors(ctx, key, kept, &res); err != nil {
		return res, err
	}
	if err := l.checkSequence(ctx, &res); err != nil {
		return res, err
	}
	return res, nil
}

// checkAnchors checks the stored anchors and the supplied ones against the
// log. An anchor that does not verify under key says nothing about the log
// and is reported as not written by this gateway; a genuine one whose event is
// gone or different is evidence of truncation or editing.
func (l *Log) checkAnchors(ctx context.Context, key []byte, kept []Anchor, res *VerifyResult) error {
	stored, err := l.Anchors(ctx)
	if err != nil {
		return err
	}
	// The hash of every event a stored anchor names, in one read (drained
	// before the next statement), and of each supplied anchor's event.
	hashes, err := l.anchoredHashes(ctx)
	if err != nil {
		return err
	}
	for _, a := range kept {
		var h string
		err := l.db.QueryRowContext(ctx, l.db.Rebind(`SELECT hash FROM audit_events WHERE id = ?`), a.EventID).Scan(&h) // #nosec G701 -- constant statement, bound args
		switch {
		case err == nil:
			hashes[a.EventID] = h
		case !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("audit: verify: read event %d: %w", a.EventID, err)
		}
	}
	var maxID sql.NullInt64
	if err := l.db.QueryRowContext(ctx, `SELECT MAX(id) FROM audit_events`).Scan(&maxID); err != nil {
		return fmt.Errorf("audit: verify: read the newest event: %w", err)
	}

	type named struct {
		Anchor
		name string
	}
	var past []named // genuine anchors naming events after the log's end
	var found []string
	check := func(a Anchor, supplied bool) {
		res.Anchors++
		name := fmt.Sprintf("anchor %d", a.ID)
		if supplied {
			name = "the supplied anchor"
		}
		if !a.Signed(key) {
			if supplied {
				name = fmt.Sprintf("the supplied anchor for event %d", a.EventID)
			}
			found = append(found, name+" was not written by this gateway: its signature does not match")
			return
		}
		h, ok := hashes[a.EventID]
		switch {
		case !ok && a.EventID > maxID.Int64:
			past = append(past, named{a, name})
		case !ok:
			found = append(found, fmt.Sprintf("%s: event %d is missing — the log was truncated or edited", name, a.EventID))
		case h != a.Hash:
			found = append(found, fmt.Sprintf("%s: event %d has changed since it was anchored — the log was edited", name, a.EventID))
		case res.LastAnchor == nil || a.EventID > res.LastAnchor.EventID:
			match := a
			res.LastAnchor = &match
		}
	}
	for _, a := range stored {
		check(a, false)
	}
	for _, a := range kept {
		check(a, true)
	}

	if len(past) > 0 {
		newest := past[0]
		for _, p := range past[1:] {
			if p.EventID > newest.EventID {
				newest = p
			}
		}
		msg := fmt.Sprintf("the log ends at event %d, but %s covers event %d: the newest events were deleted", maxID.Int64, newest.name, newest.EventID)
		if !maxID.Valid {
			msg = fmt.Sprintf("the log is empty, but %s covers event %d: every event was deleted", newest.name, newest.EventID)
		}
		if len(past) > 1 {
			msg += fmt.Sprintf(" (%d anchors name events past the end)", len(past))
		}
		res.Problems = append(res.Problems, msg)
	}
	if len(found) > maxAnchorReports {
		more := len(found) - maxAnchorReports
		found = append(found[:maxAnchorReports], fmt.Sprintf("and %d more anchor problem(s)", more))
	}
	res.Problems = append(res.Problems, found...)
	return nil
}

// anchoredHashes maps the id of every event a stored anchor names to that
// event's hash. Events that are gone are simply absent.
func (l *Log) anchoredHashes(ctx context.Context) (map[int64]string, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT e.id, e.hash FROM audit_events e JOIN audit_anchors a ON a.event_id = e.id`)
	if err != nil {
		return nil, fmt.Errorf("audit: verify: read anchored events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		var h string
		if err := rows.Scan(&id, &h); err != nil {
			return nil, fmt.Errorf("audit: verify: read anchored events: %w", err)
		}
		out[id] = h
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: verify: read anchored events: %w", err)
	}
	return out, nil
}

// checkSequence compares the high-water mark of audit_events' id sequence
// with the newest event. Deleting the newest rows leaves the chain linked
// and, until an anchor covers them, nothing else to notice; the sequence
// still remembers the ids it handed out. On SQLite the sequence row is
// written in the inserting transaction, so a rolled-back insert does not
// advance it: a mark ahead of the newest event means rows were deleted from
// the end (or the sequence row edited), a problem. A PostgreSQL sequence is
// not transactional: an insert that fails or rolls back still uses up its id,
// and a crash can skip ahead, so there the same finding is a warning.
func (l *Log) checkSequence(ctx context.Context, res *VerifyResult) error {
	if l.db.Driver == config.DriverPostgres {
		high, newest, err := l.pgSequence(ctx)
		switch {
		case err != nil:
			res.Warnings = append(res.Warnings, "the id sequence could not be read, so it was not compared with the newest event: "+err.Error())
		case high > newest:
			res.Warnings = append(res.Warnings, fmt.Sprintf("the id sequence is ahead of the newest event (%d vs %d): the newest events may have been deleted, or an insert failed", high, newest))
		}
		return nil
	}
	var seq, newest sql.NullInt64
	err := l.db.QueryRowContext(ctx, `SELECT (SELECT seq FROM sqlite_sequence WHERE name = 'audit_events'), (SELECT MAX(id) FROM audit_events)`).Scan(&seq, &newest)
	if err != nil {
		return fmt.Errorf("audit: verify: read the id sequence: %w", err)
	}
	if seq.Int64 > newest.Int64 {
		res.Problems = append(res.Problems, fmt.Sprintf("the id sequence is ahead of the newest event (%d vs %d): events were deleted from the end of the log", seq.Int64, newest.Int64))
	}
	return nil
}

// pgSequence reads the high-water mark of audit_events_id_seq (the BIGSERIAL
// sequence 0001_init.sql creates) and the newest event id together, under the
// writers' advisory lock: an insert in flight has taken its id but not yet
// committed, and would otherwise read as a deleted event.
func (l *Log) pgSequence(ctx context.Context) (high, newest int64, err error) {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockID); err != nil {
		return 0, 0, err
	}
	var last int64
	var called bool
	var maxID sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT s.last_value, s.is_called, (SELECT MAX(id) FROM audit_events) FROM audit_events_id_seq s`).Scan(&last, &called, &maxID); err != nil {
		return 0, 0, err
	}
	if called { // otherwise no id has been handed out yet
		high = last
	}
	return high, maxID.Int64, nil
}

// walk checks every link and hash of the chain, in id order.
func (l *Log) walk(ctx context.Context) (VerifyResult, error) {
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
			if ve := verifyLink(int(res.Checked), e, prev); ve != nil {
				res.Broken = ve
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
	rows, err := l.db.QueryContext(ctx, q, afterID, verifyBatchSize) // #nosec G701 -- q is the constant statement Verify builds; bound args
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

// Tally is the count of events recorded under one action and outcome.
type Tally struct {
	Action  string  `json:"action"`
	Outcome Outcome `json:"outcome"`
	Count   int64   `json:"count"`
}

// TallySince counts events at or after since, grouped by action and outcome:
// the dashboards' numbers (ADR 0029). It reads counts only — no event content
// — which is why serving it records no audit.read event. The ts index keeps
// it a range scan.
func (l *Log) TallySince(ctx context.Context, since time.Time) ([]Tally, error) {
	rows, err := l.db.QueryContext(ctx, l.db.Rebind(`SELECT action, outcome, COUNT(*) FROM audit_events WHERE ts >= ? GROUP BY action, outcome`), l.tsArg(since))
	if err != nil {
		return nil, fmt.Errorf("audit: tally: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Tally
	for rows.Next() {
		var t Tally
		if err := rows.Scan(&t.Action, &t.Outcome, &t.Count); err != nil {
			return nil, fmt.Errorf("audit: tally: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: tally: %w", err)
	}
	return out, nil
}

// CountPer counts the events of one action and outcome in each range
// between consecutive bounds, [bounds[i], bounds[i+1]) (2026-10-31, the
// dashboard's trends).
func (l *Log) CountPer(ctx context.Context, action string, outcome Outcome, bounds []time.Time) ([]int, error) {
	out := make([]int, 0, max(len(bounds)-1, 0))
	for i := 0; i+1 < len(bounds); i++ {
		var n int
		if err := l.db.QueryRowContext(ctx, l.db.Rebind(`SELECT COUNT(*) FROM audit_events WHERE action = ? AND outcome = ? AND ts >= ? AND ts < ?`),
			action, string(outcome), l.tsArg(bounds[i]), l.tsArg(bounds[i+1])).Scan(&n); err != nil {
			return nil, fmt.Errorf("audit: count: %w", err)
		}
		out = append(out, n)
	}
	return out, nil
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
	// AnchorsRemoved counts the stored anchors that named rewritten events.
	// They signed hashes that no longer exist, so they could never verify
	// again; copies kept outside the database still show the rewrite.
	AnchorsRemoved int64
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
// because each hash covers the previous row's hash. Stored anchors naming a
// rewritten event are removed in the same transaction (their hash is gone);
// an anchor naming an event that is missing is kept, so verify still reports
// the gap.
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
				if _, err := tx.ExecContext(ctx, updQ, prev, want, e.ID); err != nil { // #nosec G701 -- constant statement, bound args
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
	if res.FirstID > 0 {
		r, err := tx.ExecContext(ctx, l.db.Rebind(`DELETE FROM audit_anchors WHERE event_id >= ? AND event_id IN (SELECT id FROM audit_events)`), res.FirstID) // #nosec G701 -- constant statement, bound args
		if err != nil {
			return res, fmt.Errorf("audit: reseal: remove stale anchors: %w", err)
		}
		if res.AnchorsRemoved, err = r.RowsAffected(); err != nil {
			return res, fmt.Errorf("audit: reseal: remove stale anchors: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("audit: commit: %w", err)
	}
	return res, nil
}

// fetchBatchTx is fetchBatch bound to a transaction.
func fetchBatchTx(ctx context.Context, tx *sql.Tx, q string, afterID int64) ([]Event, error) {
	rows, err := tx.QueryContext(ctx, q, afterID, verifyBatchSize) // #nosec G701 -- q is the constant statement Reseal builds; bound args
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

// tsArg formats a timestamp for the driver: the fixed-width text every
// timestamp is stored in on SQLite (store.TimeArg), so the From and To bounds
// compare with ts as times; a native timestamptz on PostgreSQL. The hash is
// unaffected by the stored form: ComputeHash formats the parsed time.
func (l *Log) tsArg(t time.Time) any {
	if l.db.Driver == config.DriverPostgres {
		return t.UTC()
	}
	return store.TimeArg(t)
}

// tsScan accepts whatever the driver hands back for a timestamp column. Text
// is RFC 3339 of any width: the fixed form, or the nanoseconds of an event
// from a build before 1.0, which migration 0030 leaves as written because its
// hash covers every digit.
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
	rows, err := l.db.QueryContext(ctx, l.db.Rebind(selectColumns+" WHERE id > ? ORDER BY id ASC LIMIT "+strconv.Itoa(limit)), afterID) // #nosec G701 -- constant but for a bounded integer; bound args
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

// ExportBehind is how many events the given sinks have not shipped yet,
// at most: the newest event's id less the furthest-behind checkpoint
// (2026-10-31, the dashboard's integrity row). Zero with no sink.
func (l *Log) ExportBehind(ctx context.Context, sinks []string) (int64, error) {
	if len(sinks) == 0 {
		return 0, nil
	}
	var newest sql.NullInt64
	if err := l.db.QueryRowContext(ctx, `SELECT MAX(id) FROM audit_events`).Scan(&newest); err != nil {
		return 0, err
	}
	var behind int64
	for _, s := range sinks {
		at, err := l.ExportCheckpoint(ctx, s)
		if err != nil {
			return 0, err
		}
		if n := newest.Int64 - at; n > behind {
			behind = n
		}
	}
	return behind, nil
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
