// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"slices"

	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// Constraint failures are told apart by the drivers' codes, Postgres's
// SQLSTATE and SQLite's extended result code, never by message text, which a
// driver release may reword. The repos turn them into conflicts and bad
// requests; a miss is a 500.

// IsUniqueViolation reports whether err is a unique or primary-key conflict.
func IsUniqueViolation(err error) bool {
	return violates(err, "23505", sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY)
}

// IsForeignKeyViolation reports whether err is a reference to a row that does
// not exist, or the delete of a row something still references.
func IsForeignKeyViolation(err error) bool {
	return violates(err, "23503", sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY)
}

// IsCheckViolation reports whether err is a failed CHECK constraint.
func IsCheckViolation(err error) bool {
	return violates(err, "23514", sqlite3.SQLITE_CONSTRAINT_CHECK)
}

func violates(err error, sqlstate string, sqliteCodes ...int) bool {
	if pg, ok := errors.AsType[*pgconn.PgError](err); ok {
		return pg.Code == sqlstate
	}
	if lite, ok := errors.AsType[*sqlite.Error](err); ok {
		return slices.Contains(sqliteCodes, lite.Code())
	}
	return false
}
