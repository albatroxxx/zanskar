// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/store"
)

// anchorKeyInfo is the HKDF info under which the anchor key is derived from
// the master key. Changing it orphans every anchor already written.
const anchorKeyInfo = "zanskar audit anchor v1"

// anchorDomain opens every anchor MAC input, so an anchor MAC can never be
// taken for any other MAC made from the same master key.
const anchorDomain = "zanskar-audit-anchor-v1\n"

// ErrNoAnchorKey is returned when an anchor is written, re-signed or checked
// without the anchor key. Verify refuses rather than skipping the signature
// checks, so a caller that forgot the key cannot pass a forged anchor.
var ErrNoAnchorKey = errors.New("audit: the anchor key is required (derive it from the master key with AnchorKey)")

// ErrAnchorKeyMismatch is returned when the newest stored anchor is not
// signed with the key offered, so this process must not add one of its own:
// the master key was rotated and the anchors re-signed while this gateway
// kept running (restart it), or the anchor was edited (audit verify says).
// An anchor written under the old key after a rotation would fail every
// later verification, with nothing left to re-sign it.
var ErrAnchorKeyMismatch = errors.New("audit: the newest stored anchor is not signed with this gateway's key; the master key was rotated (restart the gateway) or the anchor was edited (run audit verify)")

// Anchor records the head of the chain at one moment: the newest event's id
// and hash, signed with a key derived from the master key (ADR 0008, amended
// 2026-10-11). Someone with only database access can delete an anchor but
// cannot write or alter one, so an anchor whose signature verifies proves its
// event was in the log, with that hash, when the anchor was written.
type Anchor struct {
	// ID is the audit_anchors row; 0 for an anchor kept outside the database.
	ID        int64     `json:"id"`
	EventID   int64     `json:"event_id"`
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"created_at"`
	MAC       string    `json:"mac"`
}

// AnchorKey derives the anchor-signing key from the master key with
// HKDF-SHA256. A master-key rotation changes it, which is why `zanskar key
// rotate-master` re-signs the stored anchors (ResignAnchors).
func AnchorKey(master []byte) ([]byte, error) {
	return crypto.DeriveKey(master, anchorKeyInfo)
}

// mac is HMAC-SHA256 over the domain, the event id, the hash and the time in
// RFC 3339 UTC, newline-separated. The time is formatted from the parsed
// value, never copied from input text, so equal instants always sign alike.
func (a Anchor) mac(key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(anchorDomain + strconv.FormatInt(a.EventID, 10) + "\n" + a.Hash + "\n" + a.CreatedAt.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(h.Sum(nil))
}

// Signed reports whether the anchor's MAC was made with key.
func (a Anchor) Signed(key []byte) bool {
	return len(key) > 0 && hmac.Equal([]byte(a.mac(key)), []byte(a.MAC))
}

// Line renders the anchor the way `zanskar audit anchor` prints it and
// `zanskar audit verify --anchor` reads it back.
func (a Anchor) Line() string {
	return fmt.Sprintf("anchor %d %s %s %s", a.EventID, a.Hash, a.CreatedAt.UTC().Format(time.RFC3339Nano), a.MAC)
}

// ParseAnchor reads an anchor line, "anchor <event_id> <hash> <created_at>
// <mac>"; the leading word may be left out.
func ParseAnchor(s string) (Anchor, error) {
	f := strings.Fields(s)
	if len(f) > 0 && f[0] == "anchor" {
		f = f[1:]
	}
	if len(f) != 4 {
		return Anchor{}, errors.New(`an anchor is "<event_id> <hash> <created_at> <mac>", as zanskar audit anchor prints it`)
	}
	id, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil || id <= 0 {
		return Anchor{}, fmt.Errorf("anchor event id %q is not a positive number", f[0])
	}
	at, err := time.Parse(time.RFC3339Nano, f[2])
	if err != nil {
		return Anchor{}, fmt.Errorf("anchor time %q is not an RFC 3339 time", f[2])
	}
	hash, mac := strings.ToLower(f[1]), strings.ToLower(f[3])
	if !isHex256(hash) || !isHex256(mac) {
		return Anchor{}, errors.New("an anchor's hash and mac are 64 hexadecimal characters each")
	}
	return Anchor{EventID: id, Hash: hash, CreatedAt: at.UTC(), MAC: mac}, nil
}

func isHex256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// Anchor signs the newest event and stores the anchor. When the log is empty,
// or the newest event already has an anchor signed with key, it writes
// nothing and returns the newest stored anchor (the zero Anchor if there is
// none). An anchor is never recorded as an audit event: that would move the
// head it names.
func (l *Log) Anchor(ctx context.Context, key []byte) (Anchor, error) {
	if len(key) == 0 {
		return Anchor{}, ErrNoAnchorKey
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return Anchor{}, fmt.Errorf("audit: anchor: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if l.db.Driver == config.DriverPostgres {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockID); err != nil {
			return Anchor{}, fmt.Errorf("audit: advisory lock: %w", err)
		}
	}

	var head Anchor
	err = tx.QueryRowContext(ctx, `SELECT id, hash FROM audit_events ORDER BY id DESC LIMIT 1`).Scan(&head.EventID, &head.Hash)
	empty := errors.Is(err, sql.ErrNoRows)
	if err != nil && !empty {
		return Anchor{}, fmt.Errorf("audit: anchor: read head: %w", err)
	}
	newest, err := readAnchors(ctx, tx, selectAnchors+` ORDER BY id DESC LIMIT 1`)
	if err != nil {
		return Anchor{}, err
	}
	var last Anchor
	if len(newest) > 0 {
		last = newest[0]
	}
	if empty || (last.EventID == head.EventID && last.Hash == head.Hash && last.Signed(key)) {
		return last, nil
	}
	if last.ID != 0 && !last.Signed(key) {
		return Anchor{}, ErrAnchorKeyMismatch
	}

	// PostgreSQL keeps microseconds; sign exactly what the column returns.
	head.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)
	head.MAC = head.mac(key)
	const q = `INSERT INTO audit_anchors (event_id, hash, created_at, mac) VALUES (?, ?, ?, ?)`
	args := []any{head.EventID, head.Hash, store.TimeArg(head.CreatedAt), head.MAC}
	if l.db.Driver == config.DriverPostgres {
		if err := tx.QueryRowContext(ctx, l.db.Rebind(q+` RETURNING id`), args...).Scan(&head.ID); err != nil { // #nosec G701 -- constant statement, bound args
			return Anchor{}, fmt.Errorf("audit: anchor: insert: %w", err)
		}
	} else {
		res, err := tx.ExecContext(ctx, l.db.Rebind(q), args...) // #nosec G701 -- constant statement, bound args
		if err != nil {
			return Anchor{}, fmt.Errorf("audit: anchor: insert: %w", err)
		}
		if head.ID, err = res.LastInsertId(); err != nil {
			return Anchor{}, fmt.Errorf("audit: anchor: insert id: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Anchor{}, fmt.Errorf("audit: anchor: commit: %w", err)
	}
	return head, nil
}

// Anchors returns every stored anchor, oldest first.
func (l *Log) Anchors(ctx context.Context) ([]Anchor, error) {
	return readAnchors(ctx, l.db, selectAnchors+` ORDER BY id`)
}

// ResignAnchors re-signs with newKey every stored anchor that verifies under
// oldKey. A master-key rotation changes the anchor key, and without this
// every anchor written before it would read as forged. Anchors that verify
// under neither key are left as they are, so verify keeps reporting them, and
// are counted as skipped. Running it again changes nothing.
func (l *Log) ResignAnchors(ctx context.Context, oldKey, newKey []byte) (resigned, skipped int, err error) {
	if len(oldKey) == 0 || len(newKey) == 0 {
		return 0, 0, ErrNoAnchorKey
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("audit: re-sign anchors: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if l.db.Driver == config.DriverPostgres {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockID); err != nil {
			return 0, 0, fmt.Errorf("audit: advisory lock: %w", err)
		}
	}
	// readAnchors drains and closes its cursor before the updates below:
	// SQLite runs on one connection.
	anchors, err := readAnchors(ctx, tx, selectAnchors+` ORDER BY id`)
	if err != nil {
		return 0, 0, err
	}
	upd := l.db.Rebind(`UPDATE audit_anchors SET mac = ? WHERE id = ?`)
	for _, a := range anchors {
		switch {
		case a.Signed(newKey):
		case a.Signed(oldKey):
			if _, err := tx.ExecContext(ctx, upd, a.mac(newKey), a.ID); err != nil { // #nosec G701 -- constant statement, bound args
				return 0, 0, fmt.Errorf("audit: re-sign anchor %d: %w", a.ID, err)
			}
			resigned++
		default:
			skipped++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("audit: re-sign anchors: commit: %w", err)
	}
	return resigned, skipped, nil
}

const selectAnchors = `SELECT id, event_id, hash, created_at, mac FROM audit_anchors`

// queryer is a database or a transaction.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// readAnchors runs an anchor query and returns every row, with the cursor
// closed, so the caller can issue its next statement on SQLite's single
// connection.
func readAnchors(ctx context.Context, q queryer, query string, args ...any) ([]Anchor, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: read anchors: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Anchor
	for rows.Next() {
		var a Anchor
		var at store.NullTime
		if err := rows.Scan(&a.ID, &a.EventID, &a.Hash, &at, &a.MAC); err != nil {
			return nil, fmt.Errorf("audit: read anchors: %w", err)
		}
		a.CreatedAt = at.Time
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: read anchors: %w", err)
	}
	return out, nil
}

// Anchorer signs the chain head when it starts and then every Interval
// (default one hour) until its context ends. Each new anchor is logged at
// INFO as "audit anchor" with its event id, hash, time and MAC: the service's
// journal is the copy kept outside the database, which `zanskar audit verify
// --anchor` checks the log against. A failure is logged and retried at the
// next tick; it never stops the gateway.
type Anchorer struct {
	Log      *Log
	Key      []byte
	Logger   *slog.Logger
	Interval time.Duration
}

// Run anchors until ctx ends.
func (a *Anchorer) Run(ctx context.Context) {
	every := a.Interval
	if every <= 0 {
		every = time.Hour
	}
	t := time.NewTicker(every)
	defer t.Stop()
	var logged int64
	for {
		an, err := a.Log.Anchor(ctx, a.Key)
		switch {
		case err != nil:
			if ctx.Err() == nil && a.Logger != nil {
				a.Logger.Error("audit anchor failed", "err", err)
			}
		case an.ID != 0 && an.ID != logged:
			// The time is logged as text: the text handler would round a
			// time value to milliseconds, and the MAC covers every digit.
			if a.Logger != nil {
				a.Logger.Info("audit anchor", "anchor_id", an.ID, "event_id", an.EventID, "hash", an.Hash,
					"created_at", an.CreatedAt.UTC().Format(time.RFC3339Nano), "mac", an.MAC)
			}
			logged = an.ID
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
