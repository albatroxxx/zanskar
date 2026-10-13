// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"testing"
)

type result struct {
	n   int64
	err error
}

func (r result) LastInsertId() (int64, error) { return 0, nil }
func (r result) RowsAffected() (int64, error) { return r.n, r.err }

// TestAffected: no row touched is the caller's not-found, a row touched is
// success, and a driver that cannot count passes its error through.
func TestAffected(t *testing.T) {
	notFound, broken := errors.New("not found"), errors.New("cannot count")
	if err := Affected(result{n: 0}, notFound); !errors.Is(err, notFound) {
		t.Errorf("no row: %v", err)
	}
	if err := Affected(result{n: 1}, notFound); err != nil {
		t.Errorf("one row: %v", err)
	}
	if err := Affected(result{err: broken}, notFound); !errors.Is(err, broken) {
		t.Errorf("driver error: %v", err)
	}
}
