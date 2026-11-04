// SPDX-License-Identifier: Apache-2.0

package user

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// TestSearchFindsAWordAndRanksTheClosest (2026-11-04, live walkthrough): the
// user zanskar-keykloak was found only by typing all of it. Typing "zanskar"
// lists every account with it in the username, name or email, the closest
// first: the exact name, then those that start with it, then those where it
// starts a word, then those that merely contain it. On SQLite and PostgreSQL.
func TestSearchFindsAWordAndRanksTheClosest(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		for _, u := range []*User{
			{Username: "unzanskared", DisplayName: "Contained", Email: "c@example.com"},
			{Username: "my-zanskar", DisplayName: "Word start", Email: "w@example.com"},
			{Username: "zanskar-keykloak", DisplayName: "Zanskar Man", Email: "zk@example.com"},
			{Username: "zanskar", DisplayName: "Exact", Email: "e@example.com"},
			{Username: "bob", DisplayName: "Bob Builder", Email: "bob@zanskar.example.com"},
			{Username: "alice", DisplayName: "Alice", Email: "alice@example.com"},
			{Username: "wild", DisplayName: "100% sure_thing", Email: "wild@example.com"},
		} {
			u.Roles = []Role{RoleUser}
			if err := r.Create(ctx, u); err != nil {
				t.Fatal(err)
			}
		}
		names := func(q string) []string {
			t.Helper()
			list, err := r.Search(ctx, q, 0)
			if err != nil {
				t.Fatal(err)
			}
			var out []string
			for _, u := range list {
				out = append(out, u.Username)
				if len(u.Roles) == 0 {
					t.Fatalf("%s listed without roles", u.Username)
				}
			}
			return out
		}
		eq := func(q string, want ...string) {
			t.Helper()
			if got := names(q); !slices.Equal(got, want) {
				t.Errorf("search %q lists %v, want %v", q, got, want)
			}
		}

		// exact; starts with; starts a word (my-zanskar after "-", bob's email after "@",
		// tied, so by username); merely inside.
		eq("zanskar", "zanskar", "zanskar-keykloak", "bob", "my-zanskar", "unzanskared")
		eq("ZANSKAR", "zanskar", "zanskar-keykloak", "bob", "my-zanskar", "unzanskared")
		// Part of a word finds it, a few letters in.
		eq("keyk", "zanskar-keykloak")
		// Every word must be found, in any column: "zan" and "key" of one account.
		eq("zan key", "zanskar-keykloak")
		eq("key zan", "zanskar-keykloak")
		eq("bob builder", "bob")
		// A word nobody has matches nothing; spaces alone are no search.
		eq("nobodyhasthis")
		if got := names("   "); len(got) != 7 || got[0] != "alice" {
			t.Errorf("a blank search lists everyone by username: %v", got)
		}
		// % and _ are taken literally, not as wildcards: "%" alone would match everyone.
		eq("%", "wild")
		eq("_t", "wild")
		eq("0%_")
		eq("100% sure_thing", "wild")
		// The limit holds.
		if list, err := r.Search(ctx, "zanskar", 2); err != nil || len(list) != 2 || list[0].Username != "zanskar" {
			t.Errorf("limit 2: %v %v", list, err)
		}
	})
}

// TestSearchBoundsWhatItBuilds (2026-11-04, live walkthrough of 1.18.4): a
// query of 2000 words was a 500, each word adding placeholders until the
// engine refused the statement. A search looks at the first words, each cut
// short, so any query answers, on SQLite and PostgreSQL.
func TestSearchBoundsWhatItBuilds(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		if err := r.Create(ctx, &User{Username: "zanskar", DisplayName: "Zanskar", Roles: []Role{RoleUser}}); err != nil {
			t.Fatal(err)
		}
		for name, q := range map[string]string{
			"2000 words":      strings.Repeat("zanskar ", 2000),
			"one 10k word":    strings.Repeat("a", 10000),
			"10k of wildcard": strings.Repeat("%_", 5000),
			"multibyte":       strings.Repeat("é😀", 3000),
		} {
			if _, err := r.Search(ctx, q, 0); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
		// The first words still find the account, and a long word is cut, not refused.
		if list, err := r.Search(ctx, strings.Repeat("zanskar ", 2000), 0); err != nil || len(list) != 1 {
			t.Errorf("the words it keeps: %v %v", list, err)
		}
		if list, err := r.Search(ctx, "zanskar"+strings.Repeat("x", 500), 0); err != nil || len(list) != 0 {
			t.Errorf("a word too long for any name finds nothing, quietly: %v %v", list, err)
		}
	})
}

// A search narrows a posture list too (a tile's accounts, then a word).
func TestSearchWithinAPostureList(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		for _, n := range []string{"zanskar-a", "zanskar-b", "other"} {
			if err := r.Create(ctx, &User{Username: n, DisplayName: n, PasswordHash: "hash", Roles: []Role{RoleUser}}); err != nil {
				t.Fatal(err)
			}
		}
		list, err := r.ListPosture(ctx, PostureNotEnrolled, time.Now(), nil, "zanskar")
		if err != nil || len(list) != 2 || list[0].Username != "zanskar-a" || list[1].Username != "zanskar-b" {
			t.Fatalf("posture and word: %v %v", list, err)
		}
		if list, err = r.ListPosture(ctx, PostureAdmins, time.Now(), nil, "zanskar"); err != nil || len(list) != 0 {
			t.Fatalf("a word cannot widen a posture: %v %v", list, err)
		}
	})
}
