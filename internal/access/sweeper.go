// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"log/slog"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
)

// Sweeper expires lapsed grants in the background: approved requests past their
// window become expired, and each expiry is audited (ADR 0018). The connect
// gate already enforces expiry live (it checks now < expires_at), so this is
// for state hygiene and a clean audit trail rather than for enforcement.
type Sweeper struct {
	Repo  *Repo
	Audit *audit.Log
	Log   *slog.Logger
}

// Sweep expires every grant due as of a single cutoff and audits each. It reads
// the due set and flips it under the same cutoff, so the audited set and the
// flipped set are identical.
func (s *Sweeper) Sweep(ctx context.Context) (int, error) {
	now := time.Now().UTC()
	due, err := s.Repo.DueForExpiry(ctx, now)
	if err != nil {
		return 0, err
	}
	if len(due) == 0 {
		return 0, nil
	}
	if _, err := s.Repo.ExpireDue(ctx, now); err != nil {
		return 0, err
	}
	if s.Audit != nil {
		for _, r := range due {
			ev := audit.Actor{IP: "system"}.Event("access.grant.expire", "access_request", r.ID, audit.Success,
				map[string]any{"user_id": r.UserID, "target_id": r.TargetID, "asg_id": r.ASGID, "protocol": r.Protocol})
			if _, err := s.Audit.Record(ctx, ev); err != nil {
				s.Log.Error("audit grant expire", "request", r.ID, "err", err)
			}
		}
	}
	return len(due), nil
}

// Run sweeps once immediately, then on each tick until ctx is cancelled.
func (s *Sweeper) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := s.Sweep(ctx); err != nil {
			s.Log.Error("access grant sweep", "err", err)
		} else if n > 0 {
			s.Log.Info("access grant sweep", "expired", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
