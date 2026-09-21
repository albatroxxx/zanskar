// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"log/slog"
	"time"
)

// Sink receives audit events in chain order. Delivery is at least once: a
// batch is retried until the sink accepts it, so receivers should treat the
// event id (or hash) as the idempotency key.
type Sink interface {
	// Name identifies the sink's checkpoint row.
	Name() string
	// Send delivers a batch; an error means the whole batch will be retried.
	Send(ctx context.Context, events []Event) error
}

// Exporter ships new audit events to every configured sink.
type Exporter struct {
	Log   *Log
	Sinks []Sink
	// Interval between polls. Default 5 s.
	Interval time.Duration
	// BatchSize bounds one delivery. Default 200.
	BatchSize int
	Logger    *slog.Logger
	// MaxBackoff caps the retry delay after failures. Default 5 min.
	MaxBackoff time.Duration
}

// Run polls until ctx ends. Each sink advances independently.
func (e *Exporter) Run(ctx context.Context) {
	interval := e.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	backoff := map[string]time.Duration{}
	retryAt := map[string]time.Time{}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		now := time.Now()
		for _, s := range e.Sinks {
			if until, ok := retryAt[s.Name()]; ok && now.Before(until) {
				continue
			}
			delivered, err := e.Flush(ctx, s)
			if err != nil {
				b := backoff[s.Name()]
				if b == 0 {
					b = interval
				} else {
					b *= 2
				}
				maxB := e.MaxBackoff
				if maxB <= 0 {
					maxB = 5 * time.Minute
				}
				if b > maxB {
					b = maxB
				}
				backoff[s.Name()] = b
				retryAt[s.Name()] = now.Add(b)
				if e.Logger != nil {
					e.Logger.Warn("audit export failed", "sink", s.Name(), "err", err, "retry_in", b)
				}
				continue
			}
			delete(backoff, s.Name())
			delete(retryAt, s.Name())
			if delivered > 0 && e.Logger != nil {
				e.Logger.Debug("audit export", "sink", s.Name(), "events", delivered)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Flush delivers everything after the sink's checkpoint, in batches, and
// returns how many events were accepted. It stops at the first failure so
// order is preserved.
func (e *Exporter) Flush(ctx context.Context, s Sink) (int, error) {
	size := e.BatchSize
	if size <= 0 {
		size = 200
	}
	last, err := e.Log.ExportCheckpoint(ctx, s.Name())
	if err != nil {
		return 0, err
	}
	total := 0
	for {
		batch, err := e.Log.ListAfter(ctx, last, size)
		if err != nil {
			return total, err
		}
		if len(batch) == 0 {
			return total, nil
		}
		if err := s.Send(ctx, batch); err != nil {
			return total, err
		}
		last = batch[len(batch)-1].ID
		if err := e.Log.SaveExportCheckpoint(ctx, s.Name(), last); err != nil {
			return total, err
		}
		total += len(batch)
		if len(batch) < size {
			return total, nil
		}
	}
}
