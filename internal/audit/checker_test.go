// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"
	"time"
)

// TestChecker (2026-10-31): nothing before the first check, so the dashboard
// says "not checked yet"; an intact chain checks intact; an edited event is
// a problem; Run waits its delay, then checks.
func TestChecker(t *testing.T) {
	l, db := newTestLog(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := l.Record(ctx, Actor{IP: "system"}.Event("session.start", "session", "s", Success, map[string]any{"i": i})); err != nil {
			t.Fatal(err)
		}
	}
	c := &Checker{Log: l, Key: make([]byte, 32)}
	if c.Last() != nil {
		t.Fatal("a result before any check")
	}
	if res := c.Check(ctx); !res.Intact || res.Checked != 5 || res.Problems != 0 || res.Error != "" {
		t.Fatalf("intact chain: %+v", res)
	}
	if _, err := db.ExecContext(ctx, `UPDATE audit_events SET object_id = 'edited' WHERE id = 3`); err != nil {
		t.Fatal(err)
	}
	if res := c.Check(ctx); res.Intact || res.Problems == 0 {
		t.Fatalf("an edited event must be a problem: %+v", res)
	}
	if last := c.Last(); last == nil || last.Intact {
		t.Fatalf("last: %+v", last)
	}

	run := &Checker{Log: l, Key: make([]byte, 32), Delay: 20 * time.Millisecond, Interval: time.Hour}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go run.Run(rctx)
	if run.Last() != nil {
		t.Fatal("checked before its delay")
	}
	for end := time.Now().Add(5 * time.Second); run.Last() == nil && time.Now().Before(end); {
		time.Sleep(10 * time.Millisecond)
	}
	if run.Last() == nil {
		t.Fatal("Run never checked")
	}
}

// TestExportBehind: the furthest-behind sink's distance from the newest
// event; nothing to say with no sink.
func TestExportBehind(t *testing.T) {
	l, _ := newTestLog(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := l.Record(ctx, Actor{IP: "system"}.Event("session.start", "session", "s", Success, nil)); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := l.ExportBehind(ctx, nil); err != nil || n != 0 {
		t.Fatalf("no sink: %d %v", n, err)
	}
	if err := l.SaveExportCheckpoint(ctx, "syslog", 5); err != nil {
		t.Fatal(err)
	}
	if n, err := l.ExportBehind(ctx, []string{"syslog"}); err != nil || n != 0 {
		t.Fatalf("caught up: %d %v", n, err)
	}
	if err := l.SaveExportCheckpoint(ctx, "syslog", 2); err != nil {
		t.Fatal(err)
	}
	if n, err := l.ExportBehind(ctx, []string{"syslog", "webhook"}); err != nil || n != 5 {
		t.Fatalf("webhook never shipped: %d %v, want 5", n, err)
	}
}
