// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
)

// anchorLine is how `zanskar audit anchor` prints an anchor.
var anchorLine = regexp.MustCompile(`^anchor (\d+) ([0-9a-f]{64}) (\S+) ([0-9a-f]{64})\n$`)

// TestAuditAnchorAndVerify: `audit anchor` prints the line to keep; verify
// passes an intact log and names the anchor; deleting the newest events is
// caught by the stored anchor, and, once every trace is also gone from the
// database, by the kept line through --anchor; exit codes stay 0, 1 and 2.
func TestAuditAnchorAndVerify(t *testing.T) {
	g := newCLIGateway(t, true)
	g.with(t, func(ctx context.Context, db *store.DB, _ *keyring.Ring) {
		log := audit.NewLog(db)
		for i := 0; i < 6; i++ {
			if _, err := log.Record(ctx, audit.Event{Action: "tick", Outcome: audit.Success}); err != nil {
				t.Fatal(err)
			}
		}
	})
	line, _, err := output(t, func() error { return runAuditAnchor(nil) })
	m := anchorLine.FindStringSubmatch(line)
	if err != nil || m == nil || m[1] != "6" {
		t.Fatalf("audit anchor printed %q: %v", line, err)
	}
	if again, _, err := output(t, func() error { return runAuditAnchor(nil) }); err != nil || again != line {
		t.Fatalf("with no new event, audit anchor must print the same anchor: %q %v", again, err)
	}
	kept := strings.TrimSpace(line)

	exit := func(args ...string) (int, string, string) {
		var code int
		out, stderr, _ := output(t, func() error { code = run(args); return nil })
		return code, out, stderr
	}
	if code, out, _ := exit("audit", "verify"); code != 0 || !strings.Contains(out, "intact: 6 event(s)") || !strings.Contains(out, "anchors: 1 checked; the newest covers event 6") {
		t.Fatalf("verify an intact log: exit %d\n%s", code, out)
	}
	if code, out, _ := exit("audit", "verify", "--anchor", kept); code != 0 || !strings.Contains(out, "anchors: 2 checked") {
		t.Fatalf("verify with the kept line: exit %d\n%s", code, out)
	}

	// The newest three events deleted, as a database-only attacker would.
	g.with(t, func(ctx context.Context, db *store.DB, _ *keyring.Ring) {
		if _, err := db.ExecContext(ctx, `DELETE FROM audit_events WHERE id > 3`); err != nil {
			t.Fatal(err)
		}
	})
	code, _, stderr := exit("audit", "verify")
	if code != 1 || !strings.Contains(stderr, "the log ends at event 3, but anchor 1 covers event 6: the newest events were deleted") ||
		!strings.Contains(stderr, "the id sequence is ahead of the newest event (6 vs 3)") {
		t.Fatalf("verify a truncated log: exit %d\n%s", code, stderr)
	}

	// Every trace removed from the database too: the stored checks pass, the
	// line kept outside it does not.
	g.with(t, func(ctx context.Context, db *store.DB, _ *keyring.Ring) {
		for _, q := range []string{`DELETE FROM audit_anchors`, `UPDATE sqlite_sequence SET seq = 3 WHERE name = 'audit_events'`} {
			if _, err := db.ExecContext(ctx, q); err != nil {
				t.Fatal(err)
			}
		}
	})
	if code, _, stderr := exit("audit", "verify"); code != 0 {
		t.Fatalf("with every trace gone the stored checks pass: exit %d\n%s", code, stderr)
	}
	code, _, stderr = exit("audit", "verify", "--anchor", kept)
	if code != 1 || !strings.Contains(stderr, "the log ends at event 3, but the supplied anchor covers event 6: the newest events were deleted") {
		t.Fatalf("verify against the kept line: exit %d\n%s", code, stderr)
	}

	for _, args := range [][]string{
		{"audit", "verify", "--anchor", "not an anchor"},
		{"audit", "verify", "--anchor"},
		{"audit", "verify", "extra"},
		{"audit", "anchor", "extra"},
	} {
		if code, _, _ := exit(args...); code != 2 {
			t.Errorf("zanskar %v: exit %d, want 2", args, code)
		}
	}
}

// TestAuditAnchorEmptyLogAndNoKey: an empty log has nothing to anchor, and
// the audit commands refuse to run without the master key, from which the
// anchor key is derived.
func TestAuditAnchorEmptyLogAndNoKey(t *testing.T) {
	newCLIGateway(t, true)
	if out, _, err := output(t, func() error { return runAuditAnchor(nil) }); err == nil || !strings.Contains(err.Error(), "audit log is empty") || out != "" {
		t.Fatalf("anchor an empty log: %v %q", err, out)
	}
	t.Setenv("ZANSKAR_MASTER_KEY", "")
	for _, fn := range []func() error{
		func() error { return runAuditVerify(nil) },
		func() error { return runAuditAnchor(nil) },
		func() error { return runAuditReseal([]string{"--yes"}) },
	} {
		if _, _, err := output(t, fn); err == nil || !strings.Contains(err.Error(), "ZANSKAR_MASTER_KEY") {
			t.Fatalf("an audit command without the master key: %v", err)
		}
	}
}
