// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
)

// runAudit handles `zanskar audit <subcommand>`.
func runAudit(args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprintln(os.Stderr, "usage: zanskar audit verify")
		os.Exit(2)
	}
	cfg, err := config.Load(config.Options{})
	if err != nil {
		return err
	}
	ctx := context.Background()
	db, err := store.Open(ctx, cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		return err
	}
	defer db.Close()

	res, err := audit.NewLog(db).Verify(ctx)
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
