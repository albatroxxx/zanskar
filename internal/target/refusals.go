// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
)

// Refusal is one thing an application's sessions were refused as a
// dependency (ADR 0037, amended 2026-11-03, later), learned from the relay's
// log and kept per application: the destination, why, what asked for it
// (the browser's fetch destination) and the page's origin, counted over
// every session since it was first seen.
type Refusal struct {
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Why       string    `json:"why"`
	What      string    `json:"what"`
	From      string    `json:"from"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// MaxRefusalsListed bounds what one application's list shows, newest first.
const MaxRefusalsListed = 200

// RecordRefusals adds what a session's relay refused to the application's
// list: a row per destination, reason, kind and page, its count carried on
// and its last sighting moved up. Each row's time is the sighting's.
func (r *Repo) RecordRefusals(ctx context.Context, targetID string, rs []Refusal) error {
	if len(rs) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	q := r.db.Rebind(`INSERT INTO app_dependency_refusals (target_id, host, port, why, what, from_origin, count, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (target_id, host, port, why, what, from_origin)
		DO UPDATE SET count = app_dependency_refusals.count + excluded.count, last_seen = excluded.last_seen`)
	for _, x := range rs {
		at := x.LastSeen
		if at.IsZero() {
			at = time.Now()
		}
		first := x.FirstSeen
		if first.IsZero() {
			first = at
		}
		n := x.Count
		if n < 1 {
			n = 1
		}
		if _, err := tx.ExecContext(ctx, q, targetID, x.Host, x.Port, x.Why, x.What, x.From, n, store.TimeArg(first.UTC()), store.TimeArg(at.UTC())); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListRefusals is an application's list, newest sighting first.
func (r *Repo) ListRefusals(ctx context.Context, targetID string) ([]Refusal, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT host, port, why, what, from_origin, count, first_seen, last_seen
		FROM app_dependency_refusals WHERE target_id = ? ORDER BY last_seen DESC, host, port LIMIT ?`), targetID, MaxRefusalsListed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Refusal{}
	for rows.Next() {
		var x Refusal
		var first, last store.NullTime
		if err := rows.Scan(&x.Host, &x.Port, &x.Why, &x.What, &x.From, &x.Count, &first, &last); err != nil {
			return nil, err
		}
		x.FirstSeen, x.LastSeen = first.Time, last.Time
		out = append(out, x)
	}
	return out, rows.Err()
}

// ClearRefusals forgets an application's list.
func (r *Repo) ClearRefusals(ctx context.Context, targetID string) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM app_dependency_refusals WHERE target_id = ?`), targetID)
	return err
}
