// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
)

// openDB loads the configuration and opens the database for a command that
// works on it offline (not serve, which runs its own checks at start). A
// database with migrations pending is refused, with what to run: the code
// expects the current schema, and working on an older one fails in ways that
// say nothing useful (or, worse, half-works).
func openDB(ctx context.Context, opts config.Options) (*config.Config, *store.DB, error) {
	cfg, err := config.Load(opts)
	if err != nil {
		return nil, nil, err
	}
	db, err := store.Open(ctx, cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		return nil, nil, err
	}
	pending, err := store.Pending(ctx, db)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	if len(pending) > 0 {
		_ = db.Close()
		return nil, nil, fmt.Errorf("%d migration(s) pending; run `zanskar migrate` first", len(pending))
	}
	return cfg, db, nil
}
