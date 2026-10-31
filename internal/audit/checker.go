// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// CheckResult is the last full verification of the chain, as the
// dashboard shows it.
type CheckResult struct {
	At time.Time `json:"at"`
	// Intact: every link and hash held, and the anchor and sequence checks
	// found nothing.
	Intact bool `json:"intact"`
	// Checked is how many events were walked; Problems how many things the
	// walk, the anchors and the sequence check found.
	Checked  int64 `json:"checked"`
	Problems int   `json:"problems"`
	// Error is a check that could not run (I/O), which says nothing about
	// the chain either way.
	Error string `json:"error,omitempty"`
}

// Checker verifies the whole chain in the background for the dashboard
// (2026-10-31): first Delay after start, so it does not land on top of the
// first page loads, then every Interval. A walk of 20,000 events took 79 ms
// on SQLite (measured), and it reads in batches, so other queries go on
// between them. The last result lives in memory: a restart forgets it, and
// before the first run the dashboard says the chain has not been checked,
// never that it is intact.
type Checker struct {
	Log      *Log
	Key      []byte
	Logger   *slog.Logger
	Delay    time.Duration // default one minute
	Interval time.Duration // default six hours

	mu   sync.Mutex
	last *CheckResult
}

// Last is the most recent result, nil before the first check.
func (c *Checker) Last() *CheckResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last == nil {
		return nil
	}
	cp := *c.last
	return &cp
}

// Check verifies once and keeps the result.
func (c *Checker) Check(ctx context.Context) CheckResult {
	res := CheckResult{At: time.Now().UTC()}
	v, err := c.Log.Verify(ctx, c.Key)
	switch {
	case err != nil:
		res.Error = err.Error()
	default:
		res.Checked, res.Intact, res.Problems = v.Checked, v.Intact(), len(v.Problems)
		if v.Broken != nil {
			res.Problems++
		}
	}
	if !res.Intact && c.Logger != nil {
		c.Logger.Error("audit chain check found a problem", "problems", res.Problems, "error", res.Error)
	}
	c.mu.Lock()
	c.last = &res
	c.mu.Unlock()
	return res
}

// Run checks after Delay and then every Interval until ctx ends.
func (c *Checker) Run(ctx context.Context) {
	delay, every := c.Delay, c.Interval
	if delay <= 0 {
		delay = time.Minute
	}
	if every <= 0 {
		every = 6 * time.Hour
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(delay):
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		c.Check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
