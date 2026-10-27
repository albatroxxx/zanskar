// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"testing"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// TestListQueryEscapesLikeOnEachBackend: the search box's text is a
// substring, never a pattern. `_` must not match any character, `%` must not
// match everything, and a trailing backslash must not swallow the closing
// wildcard; the same on SQLite and PostgreSQL, whose LIKE differ in default
// escaping (review Q1, finding 1c; the mutation that dropped the escaping
// survived every test).
func TestListQueryEscapesLikeOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		for i, name := range []string{"ab", "a_b", "axb", "a-b", "Backslash"} {
			tg := &Target{Name: name, Address: "10.0.0." + string(rune('1'+i)), OSFamily: Linux, Tags: map[string]string{"env": "test"}}
			if err := r.Create(ctx, tg); err != nil {
				t.Fatalf("create %s: %v", name, err)
			}
		}
		names := func(q string) []string {
			t.Helper()
			out, _, err := r.List(ctx, "", 50, ListFilter{Query: q})
			if err != nil {
				t.Fatalf("List(%q): %v", q, err)
			}
			got := make([]string, 0, len(out))
			for _, tg := range out {
				got = append(got, tg.Name)
			}
			return got
		}
		if got := names("a_b"); len(got) != 1 || got[0] != "a_b" {
			t.Fatalf("an underscore must match itself only: %v", got)
		}
		if got := names("%"); len(got) != 0 {
			t.Fatalf("a percent sign must match nothing, not everything: %v", got)
		}
		if got := names(`a\`); len(got) != 0 {
			t.Fatalf("a trailing backslash must match nothing and not break the pattern: %v", got)
		}
		if got := names("BACK"); len(got) != 1 || got[0] != "Backslash" {
			t.Fatalf("the search is case-insensitive on name: %v", got)
		}
		if got := names("10.0.0.1"); len(got) != 1 || got[0] != "ab" {
			t.Fatalf("the search covers the address: %v", got)
		}
		if got := names("a"); len(got) != 5 {
			t.Fatalf("a plain substring matches every name holding it: %v", got)
		}
	})
}
