// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
)

// runAudit handles `zanskar audit <subcommand>`.
func runAudit(args []string) error {
	if len(args) == 0 {
		auditUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "verify":
		return runAuditVerify()
	case "reseal":
		return runAuditReseal(args[1:])
	default:
		auditUsage()
		os.Exit(2)
		return nil
	}
}

func auditUsage() {
	fmt.Fprintln(os.Stderr, "usage: zanskar audit <verify|reseal>")
	fmt.Fprintln(os.Stderr, "  verify   walk the chain and check every event's hash")
	fmt.Fprintln(os.Stderr, "  reseal   rewrite the chain after a hash-computation bug (destructive; needs --yes)")
}

// openLog loads the config and returns the audit log plus a close func.
func openLog() (*audit.Log, func(), error) {
	cfg, err := config.Load(config.Options{})
	if err != nil {
		return nil, nil, err
	}
	db, err := store.Open(context.Background(), cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		return nil, nil, err
	}
	return audit.NewLog(db), func() { _ = db.Close() }, nil
}

func runAuditVerify() error {
	log, closeDB, err := openLog()
	if err != nil {
		return err
	}
	defer closeDB()

	res, err := log.Verify(context.Background())
	if err != nil {
		return err
	}
	if res.Broken != nil {
		fmt.Fprintf(os.Stderr, "audit chain BROKEN: %s\n%d event(s) verified before the break; last good id %d hash %s\n",
			res.Broken.Reason, res.Checked, res.LastID, res.LastHash)
		return errors.New("audit log integrity check failed")
	}
	fmt.Printf("audit chain intact: %d event(s) verified, last id %d, head hash %s\n", res.Checked, res.LastID, res.LastHash)
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
		fmt.Fprintln(os.Stderr, "tampering and a repair look identical. Only run it when you know why the")
		fmt.Fprintln(os.Stderr, "chain broke. Re-run with --yes to proceed.")
		return errors.New("refusing to reseal without --yes")
	}

	log, closeDB, err := openLog()
	if err != nil {
		return err
	}
	defer closeDB()
	ctx := context.Background()

	before, err := log.Verify(ctx)
	if err != nil {
		return err
	}
	if before.Broken == nil {
		fmt.Printf("audit chain already intact: %d event(s); nothing to reseal\n", before.Checked)
		return nil
	}
	fmt.Printf("chain breaks at id %d (%s); resealing…\n", before.Broken.ID, before.Broken.Reason)

	res, err := log.Reseal(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("resealed: %d event(s) scanned, %d rewritten (ids %d..%d), head %s\n",
		res.Scanned, res.Rewritten, res.FirstID, res.LastID, res.Head)

	// Record the reseal in the log it just rewrote, so the act is visible.
	details, err := json.Marshal(map[string]any{
		"rows_scanned":   res.Scanned,
		"rows_rewritten": res.Rewritten,
		"first_id":       res.FirstID,
		"last_id":        res.LastID,
		"broke_at_id":    before.Broken.ID,
		"reason":         before.Broken.Reason,
	})
	if err != nil {
		return err
	}
	if _, err := log.Record(ctx, audit.Event{
		Action:     "audit.reseal",
		ObjectType: "audit_log",
		Outcome:    audit.Success,
		Details:    details,
	}); err != nil {
		return fmt.Errorf("reseal recorded no audit event: %w", err)
	}

	after, err := log.Verify(ctx)
	if err != nil {
		return err
	}
	if after.Broken != nil {
		return fmt.Errorf("chain still broken after reseal at id %d: %s", after.Broken.ID, after.Broken.Reason)
	}
	fmt.Printf("audit chain intact: %d event(s) verified, last id %d, head hash %s\n", after.Checked, after.LastID, after.LastHash)
	return nil
}
