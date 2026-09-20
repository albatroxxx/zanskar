// SPDX-License-Identifier: Apache-2.0

package store

import (
	"database/sql/driver"
	"fmt"
	"time"
)

// TimeArg formats a time for storage. Both drivers receive an RFC 3339 UTC
// string: SQLite keeps it as TEXT, PostgreSQL casts it to TIMESTAMPTZ.
func TimeArg(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// NullTime scans a nullable timestamp from either driver.
type NullTime struct {
	Time  time.Time
	Valid bool
}

// Scan implements sql.Scanner.
func (n *NullTime) Scan(src any) error {
	n.Time, n.Valid = time.Time{}, false
	switch v := src.(type) {
	case nil:
		return nil
	case time.Time:
		n.Time, n.Valid = v.UTC(), true
		return nil
	case string:
		return n.parse(v)
	case []byte:
		return n.parse(string(v))
	default:
		return fmt.Errorf("store: cannot scan %T into NullTime", src)
	}
}

func (n *NullTime) parse(s string) error {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return fmt.Errorf("store: bad timestamp %q: %w", s, err)
	}
	n.Time, n.Valid = t.UTC(), true
	return nil
}

// Value implements driver.Valuer so NullTime can also be passed as an argument.
func (n NullTime) Value() (driver.Value, error) {
	if !n.Valid {
		return nil, nil
	}
	return TimeArg(n.Time), nil
}

// Ptr returns the time as a pointer, nil when not valid.
func (n NullTime) Ptr() *time.Time {
	if !n.Valid {
		return nil
	}
	t := n.Time
	return &t
}
