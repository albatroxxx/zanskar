// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/config"
)

// runAudit handles `zanskar audit <subcommand>`.
func runAudit(args []string) error {
	if len(args) == 0 {
		auditUsage()
		return errUsage
	}
	switch args[0] {
	case "verify":
		return runAuditVerify(args[1:])
	case "anchor":
		return runAuditAnchor(args[1:])
	case "reseal":
		return runAuditReseal(args[1:])
	default:
		auditUsage()
		return errUsage
	}
}

func auditUsage() {
	fmt.Fprintln(os.Stderr, "usage: zanskar audit <verify|anchor|reseal>")
	fmt.Fprintln(os.Stderr, "  verify [--anchor LINE]...  check every event's hash, the signed anchors and the id sequence;")
	fmt.Fprintln(os.Stderr, "                             --anchor also checks a line kept outside the database")
	fmt.Fprintln(os.Stderr, "  anchor   sign the newest event now and print the line to keep outside the database")
	fmt.Fprintln(os.Stderr, "  reseal   rewrite the chain after a hash-computation bug (destructive; needs --yes)")
}

// openLog loads the config and returns the audit log, the anchor key derived
// from the master key, and a close func. Every audit command needs the key:
// verify checks the anchors' signatures with it and refuses to run without.
func openLog() (*audit.Log, []byte, func(), error) {
	cfg, db, err := openDB(context.Background(), config.Options{RequireMasterKey: true})
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := audit.AnchorKey(cfg.MasterKey)
	if err != nil {
		_ = db.Close()
		return nil, nil, nil, err
	}
	return audit.NewLog(db), key, func() { _ = db.Close() }, nil
}

// runAuditVerify walks the chain and checks the anchors and the id sequence.
// It exits 0 when the log is intact, 1 when it is not, and 2 on a malformed
// command line, including an --anchor value that is not an anchor line.
func runAuditVerify(args []string) error {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	var kept []audit.Anchor
	fs.Func("anchor", `an anchor kept outside the database, "<event_id> <hash> <created_at> <mac>" as zanskar audit anchor prints it (repeatable)`, func(s string) error {
		a, err := audit.ParseAnchor(s)
		if err != nil {
			return err
		}
		kept = append(kept, a)
		return nil
	})
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() > 0 {
		auditUsage()
		return errUsage
	}
	log, key, closeDB, err := openLog()
	if err != nil {
		return err
	}
	defer closeDB()

	res, err := log.Verify(context.Background(), key, kept...)
	if err != nil {
		return err
	}
	return reportVerify(res)
}

// reportVerify prints a verify result: the summary on stdout when the log is
// intact, every finding on stderr when it is not.
func reportVerify(res audit.VerifyResult) error {
	for _, w := range res.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	if !res.Intact() {
		if res.Broken != nil {
			fmt.Fprintf(os.Stderr, "audit chain BROKEN: %s\n%d event(s) verified before the break; last good id %d hash %s\n",
				res.Broken.Reason, res.Checked, res.LastID, res.LastHash)
		}
		for _, p := range res.Problems {
			fmt.Fprintln(os.Stderr, "audit log problem:", p)
		}
		if a := res.LastAnchor; a != nil {
			fmt.Fprintf(os.Stderr, "last matching anchor: event %d, written %s\n", a.EventID, a.CreatedAt.UTC().Format(time.RFC3339))
		}
		return errors.New("audit log integrity check failed")
	}
	fmt.Printf("audit chain intact: %d event(s) verified, last id %d, head hash %s\n", res.Checked, res.LastID, res.LastHash)
	if a := res.LastAnchor; a != nil {
		fmt.Printf("anchors: %d checked; the newest covers event %d, written %s\n", res.Anchors, a.EventID, a.CreatedAt.UTC().Format(time.RFC3339))
	} else {
		fmt.Println("anchors: none yet; the gateway writes one at start and every hour, or run zanskar audit anchor")
	}
	return nil
}

// runAuditAnchor signs the newest event now and prints the anchor line, for
// an operator to keep somewhere the database's administrators cannot edit.
// When the newest event is already anchored it prints that anchor.
func runAuditAnchor(args []string) error {
	if len(args) > 0 {
		auditUsage()
		return errUsage
	}
	log, key, closeDB, err := openLog()
	if err != nil {
		return err
	}
	defer closeDB()
	a, err := log.Anchor(context.Background(), key)
	if err != nil {
		return err
	}
	if a.EventID == 0 {
		return errors.New("nothing to anchor: the audit log is empty")
	}
	fmt.Println(a.Line())
	return nil
}

// runAuditReseal rewrites the chain so a log broken by a hash-computation bug
// verifies again. It is deliberately awkward to run: the rewrite is permanent
// and removes the chain's evidence that the affected rows were never altered.
func runAuditReseal(args []string) error {
	confirmed := false
	for _, a := range args {
		if a == "--yes" {
			confirmed = true
		}
	}
	if !confirmed {
		fmt.Fprintln(os.Stderr, "audit reseal rewrites every stored hash from the first mismatch to the head.")
		fmt.Fprintln(os.Stderr, "It makes the log verifiable again, but it permanently destroys the chain's")
		fmt.Fprintln(os.Stderr, "evidence that those rows were never altered: after a reseal, a genuine")
		fmt.Fprintln(os.Stderr, "tampering and a repair look identical. Stored anchors over the rewritten")
		fmt.Fprintln(os.Stderr, "events are removed with it, and anchor lines kept elsewhere for them will no")
		fmt.Fprintln(os.Stderr, "longer verify. Only run it when you know why the chain broke. Re-run with")
		fmt.Fprintln(os.Stderr, "--yes to proceed.")
		return errors.New("refusing to reseal without --yes")
	}

	log, key, closeDB, err := openLog()
	if err != nil {
		return err
	}
	defer closeDB()
	ctx := context.Background()

	before, err := log.Verify(ctx, key)
	if err != nil {
		return err
	}
	if before.Broken == nil {
		fmt.Printf("audit chain already intact: %d event(s); nothing to reseal\n", before.Checked)
		if len(before.Problems) > 0 {
			fmt.Println("zanskar audit verify reports other problems, which a reseal cannot repair.")
		}
		return nil
	}
	fmt.Printf("chain breaks at id %d (%s); resealing…\n", before.Broken.ID, before.Broken.Reason)

	res, err := log.Reseal(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("resealed: %d event(s) scanned, %d rewritten (ids %d..%d), head %s; %d anchor(s) over rewritten events removed\n",
		res.Scanned, res.Rewritten, res.FirstID, res.LastID, res.Head, res.AnchorsRemoved)

	// Record the reseal in the log it just rewrote, so the act is visible.
	details, err := json.Marshal(map[string]any{
		"rows_scanned":    res.Scanned,
		"rows_rewritten":  res.Rewritten,
		"first_id":        res.FirstID,
		"last_id":         res.LastID,
		"broke_at_id":     before.Broken.ID,
		"reason":          before.Broken.Reason,
		"anchors_removed": res.AnchorsRemoved,
	})
	if err != nil {
		return err
	}
	if _, err := log.Record(ctx, audit.Event{
		Action:     audit.AuditReseal,
		ObjectType: "audit_log",
		Outcome:    audit.Success,
		Details:    details,
	}); err != nil {
		return fmt.Errorf("reseal recorded no audit event: %w", err)
	}
	// Anchor the resealed head straight away, so the rewrite is covered.
	anchor, err := log.Anchor(ctx, key)
	if err != nil {
		return fmt.Errorf("resealed, but the new head could not be anchored: %w", err)
	}
	fmt.Println("anchored the resealed head; keep this line outside the database:")
	fmt.Println(anchor.Line())

	after, err := log.Verify(ctx, key)
	if err != nil {
		return err
	}
	if after.Broken != nil {
		return fmt.Errorf("chain still broken after reseal at id %d: %s", after.Broken.ID, after.Broken.Reason)
	}
	return reportVerify(after)
}
