// SPDX-License-Identifier: Apache-2.0

package store

import (
	"database/sql/driver"
	"fmt"
	"time"
)

// timeLayout is the stored form of a timestamp: RFC 3339 in UTC with exactly
// six fractional digits. SQLite keeps timestamps as TEXT and compares them
// byte by byte, so the form must be fixed-width for text order to be time
// order; with trailing zeros trimmed, "…T10:00:00.5Z" sorted before
// "…T10:00:00Z" ('.' < 'Z'). Six digits are the microseconds PostgreSQL's
// TIMESTAMPTZ keeps (ADR 0003, amended 2026-10-11).
const timeLayout = "2006-01-02T15:04:05.000000Z"

// TimeArg formats a time for storage, truncated to the microsecond. Both
// drivers receive the same fixed-width UTC string: SQLite keeps it as TEXT,
// PostgreSQL casts it to TIMESTAMPTZ. Every timestamp written or compared in
// SQL goes through it, so stored values and bounds compare as times.
func TimeArg(t time.Time) string {
	return t.UTC().Format(timeLayout)
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

// parse accepts any RFC 3339 time, not only the fixed form TimeArg writes: a
// value in the form written before migration 0030 (fraction trimmed, or whole
// seconds) still reads.
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
