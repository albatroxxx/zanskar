// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/store"
)

// RetentionPolicy is the admin-editable rule for deleting old recordings
// (ADR 0015). MaxAgeDays keeps recordings for that many days; MaxTotalBytes is a
// backstop that deletes the oldest early if the total would exceed it. Zero
// disables that dimension, and both zero means keep everything.
type RetentionPolicy struct {
	MaxAgeDays    int        `json:"max_age_days"`
	MaxTotalBytes int64      `json:"max_total_bytes"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
	UpdatedBy     string     `json:"updated_by,omitempty"`
}

const retentionPolicyID = "default"

// GetRetentionPolicy returns the current policy, or the zero policy (retention
// off) when none has been set.
func (r *Repo) GetRetentionPolicy(ctx context.Context) (RetentionPolicy, error) {
	var (
		p       RetentionPolicy
		updated store.NullTime
		by      sql.NullString
	)
	err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT max_age_days, max_total_bytes, updated_at, updated_by FROM retention_policy WHERE id = ?`), retentionPolicyID).
		Scan(&p.MaxAgeDays, &p.MaxTotalBytes, &updated, &by)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RetentionPolicy{}, nil
		}
		return RetentionPolicy{}, err
	}
	p.UpdatedAt, p.UpdatedBy = updated.Ptr(), by.String
	return p, nil
}

// SetRetentionPolicy upserts the policy and stamps who changed it.
func (r *Repo) SetRetentionPolicy(ctx context.Context, p RetentionPolicy, actorUserID string) error {
	if p.MaxAgeDays < 0 || p.MaxTotalBytes < 0 {
		return fmt.Errorf("retention: values must not be negative")
	}
	now := time.Now().UTC()
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO retention_policy (id, max_age_days, max_total_bytes, updated_at, updated_by)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET max_age_days = excluded.max_age_days, max_total_bytes = excluded.max_total_bytes, updated_at = excluded.updated_at, updated_by = excluded.updated_by`),
		retentionPolicyID, p.MaxAgeDays, p.MaxTotalBytes, store.TimeArg(now), sql.NullString{String: actorUserID, Valid: actorUserID != ""})
	return err
}

// purgeCandidate is a finished, not-yet-purged recording the sweeper may delete.
type purgeCandidate struct {
	id       string
	uri      string
	size     int64
	finished time.Time
}

// listPurgeCandidates returns finished recordings whose blob still exists,
// oldest first. The whole set is read before any delete runs, which the
// single-connection SQLite setup requires.
func (r *Repo) listPurgeCandidates(ctx context.Context) ([]purgeCandidate, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT id, storage_uri, size_bytes, finished_at
		FROM recordings WHERE purged_at IS NULL AND finished_at IS NOT NULL ORDER BY finished_at ASC`))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []purgeCandidate
	for rows.Next() {
		var (
			c        purgeCandidate
			finished store.NullTime
		)
		if err := rows.Scan(&c.id, &c.uri, &c.size, &finished); err != nil {
			return nil, err
		}
		c.finished = finished.Time
		out = append(out, c)
	}
	return out, rows.Err()
}

// markRecordingPurged records that a recording's blob was deleted, keeping the
// metadata row so audit events that reference it still resolve.
func (r *Repo) markRecordingPurged(ctx context.Context, id string, when time.Time) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE recordings SET purged_at = ? WHERE id = ?`), store.TimeArg(when), id)
	return err
}

// selectForPurge decides which candidates to delete under the policy and why.
// Age comes first; the size backstop then removes the oldest survivors until the
// kept total is within the cap. It is pure so the decision is unit-tested apart
// from storage and the database.
func selectForPurge(cands []purgeCandidate, p RetentionPolicy, now time.Time) map[string]string {
	reason := make(map[string]string)
	var keptBytes int64
	cutoff := now.AddDate(0, 0, -p.MaxAgeDays)
	// Oldest first (as queried); age-expired go, the rest are provisionally kept.
	var survivors []purgeCandidate
	for _, c := range cands {
		if p.MaxAgeDays > 0 && c.finished.Before(cutoff) {
			reason[c.id] = "age"
			continue
		}
		survivors = append(survivors, c)
		keptBytes += c.size
	}
	// Size backstop: drop oldest survivors until within the cap.
	if p.MaxTotalBytes > 0 {
		for _, c := range survivors {
			if keptBytes <= p.MaxTotalBytes {
				break
			}
			reason[c.id] = "size"
			keptBytes -= c.size
		}
	}
	return reason
}

// RetentionSweeper deletes recordings past the policy and records each purge.
type RetentionSweeper struct {
	Repo    *Repo
	Storage recording.Storage
	Audit   *audit.Log
	Log     *slog.Logger
}

// Sweep applies the current policy once and returns how many blobs it deleted.
func (s *RetentionSweeper) Sweep(ctx context.Context) (int, error) {
	policy, err := s.Repo.GetRetentionPolicy(ctx)
	if err != nil {
		return 0, err
	}
	if policy.MaxAgeDays == 0 && policy.MaxTotalBytes == 0 {
		return 0, nil // retention disabled
	}
	cands, err := s.Repo.listPurgeCandidates(ctx)
	if err != nil {
		return 0, err
	}
	reasons := selectForPurge(cands, policy, time.Now().UTC())
	purged := 0
	for _, c := range cands {
		reason, ok := reasons[c.id]
		if !ok {
			continue
		}
		if err := s.Storage.Delete(ctx, c.uri); err != nil {
			// Leave the row unpurged so the next sweep retries.
			s.Log.Error("retention: delete blob", "recording", c.id, "err", err)
			continue
		}
		if err := s.Repo.markRecordingPurged(ctx, c.id, time.Now().UTC()); err != nil {
			s.Log.Error("retention: mark purged", "recording", c.id, "err", err)
			continue
		}
		if s.Audit != nil {
			if _, err := s.Audit.Record(ctx, audit.Actor{IP: "system"}.Event("recording.purge", "recording", c.id, audit.Success,
				map[string]any{"reason": reason, "bytes": c.size})); err != nil {
				s.Log.Error("retention: audit purge", "recording", c.id, "err", err)
			}
		}
		purged++
	}
	return purged, nil
}

// Run sweeps on start and then every interval until ctx is cancelled.
func (s *RetentionSweeper) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := s.Sweep(ctx); err != nil {
			s.Log.Error("retention sweep", "err", err)
		} else if n > 0 {
			s.Log.Info("retention sweep", "purged", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
