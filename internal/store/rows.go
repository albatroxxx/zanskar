// SPDX-License-Identifier: Apache-2.0

package store

import "database/sql"

// Scanner is a row to scan: *sql.Row and *sql.Rows both satisfy it, so a
// repo's one scan function serves its Get and its List alike.
type Scanner interface{ Scan(dest ...any) error }

// Affected returns notFound when res touched no row: an update or delete
// whose WHERE matched nothing, which to its caller means the row is not
// there, or no longer is.
func Affected(res sql.Result, notFound error) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return notFound
	}
	return nil
}
