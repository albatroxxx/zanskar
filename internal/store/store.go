// SPDX-License-Identifier: Apache-2.0

// Package store opens the database and runs migrations. Query code lives in
// per-domain packages; this package only owns the connection and the schema.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // postgres driver
	_ "modernc.org/sqlite"             // sqlite driver (pure Go)

	"github.com/albatroxxx/zanskar/internal/config"
)

// DB wraps database/sql with the driver name, which query code needs for the
// few places where dialects differ (placeholders, RETURNING).
type DB struct {
	*sql.DB
	Driver string
}

// Open connects and verifies the connection. It does not migrate.
func Open(ctx context.Context, driver, dsn string) (*DB, error) {
	var sqlDriver string
	switch driver {
	case config.DriverSQLite:
		sqlDriver = "sqlite"
	case config.DriverPostgres:
		sqlDriver = "pgx"
	default:
		return nil, fmt.Errorf("store: unknown driver %q", driver)
	}
	db, err := sql.Open(sqlDriver, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	if driver == config.DriverSQLite {
		// SQLite serialises writers; a single connection avoids SQLITE_BUSY storms
		// and keeps PRAGMAs applied consistently.
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(20)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(30 * time.Minute)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &DB{DB: db, Driver: driver}, nil
}

// Rebind converts ? placeholders to the dialect's form. Query code writes ?
// and calls Rebind once per statement.
func (d *DB) Rebind(query string) string {
	if d.Driver != config.DriverPostgres {
		return query
	}
	out := make([]byte, 0, len(query)+8)
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			out = append(out, '$')
			out = append(out, []byte(fmt.Sprint(n))...)
			continue
		}
		out = append(out, query[i])
	}
	return string(out)
}
