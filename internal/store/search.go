// SPDX-License-Identifier: Apache-2.0

package store

import (
	"strings"
)

// Search is a case-insensitive search over text columns that finds a word
// anywhere in them and puts the closest match first (2026-11-04: a user named
// zanskar-keykloak was found only by typing all of it). It is SQL both
// engines run, not a search service: LOWER() and LIKE ... ESCAPE, the same
// statements a plain filter would use, so a gateway keeps its one database
// and nothing to run beside it.
//
// Every word of the query must appear in at least one of the columns. How
// close a match is, per word, is the best any column offers:
//
//	0 a column is exactly the word
//	1 a column starts with it
//	2 it starts a word inside a column (after a space, "-", "_", ".", "@" or "/")
//	3 it appears somewhere inside
//
// and a row's rank is the sum over the words, so "zanskar key" puts a name
// that starts with both before one that merely contains them. A NULL column
// matches nothing.
type Search struct {
	// Where holds the conditions, as "(...) AND (...)", with WhereArgs for its
	// placeholders; put it after WHERE (or AND).
	Where     string
	WhereArgs []any
	// Rank is an expression, smaller for a closer match, with RankArgs for its
	// placeholders; put it in ORDER BY, after the WHERE arguments have been
	// bound, then break ties on the column the list is otherwise sorted by.
	Rank     string
	RankArgs []any
}

// separators begin a word inside a value.
const separators = " -_./@"

// NewSearch builds the Search for query over cols, each a column expression
// such as "u.username". It reports false for a query of only spaces, which
// matches everything and ranks nothing.
func NewSearch(query string, cols ...string) (Search, bool) {
	words := strings.Fields(strings.ToLower(query))
	if len(words) == 0 || len(cols) == 0 {
		return Search{}, false
	}
	var s Search
	var wheres, ranks []string
	for _, w := range words {
		e := likeEscape(w)
		// Each tier is "some column fits", so the rank is the best column's, and
		// the ordered CASE needs no engine-specific LEAST or MIN.
		var contains, exact, starts, wordStarts []string
		for _, c := range cols {
			lc := "LOWER(" + c + ")"
			contains = append(contains, lc+` LIKE ? ESCAPE '\'`)
			exact = append(exact, lc+" = ?")
			starts = append(starts, lc+` LIKE ? ESCAPE '\'`)
		}
		for _, c := range cols {
			for range separators {
				wordStarts = append(wordStarts, "LOWER("+c+")"+` LIKE ? ESCAPE '\'`)
			}
		}
		// Arguments in the order the placeholders appear.
		for range cols {
			s.WhereArgs = append(s.WhereArgs, "%"+e+"%")
		}
		for range cols {
			s.RankArgs = append(s.RankArgs, w)
		}
		for range cols {
			s.RankArgs = append(s.RankArgs, e+"%")
		}
		for range cols {
			for _, sep := range separators {
				s.RankArgs = append(s.RankArgs, "%"+likeEscape(string(sep))+e+"%")
			}
		}
		for range cols {
			s.RankArgs = append(s.RankArgs, "%"+e+"%")
		}
		wheres = append(wheres, "("+strings.Join(contains, " OR ")+")")
		ranks = append(ranks, "CASE WHEN ("+strings.Join(exact, " OR ")+") THEN 0 WHEN ("+strings.Join(starts, " OR ")+
			") THEN 1 WHEN ("+strings.Join(wordStarts, " OR ")+") THEN 2 WHEN ("+strings.Join(contains, " OR ")+") THEN 3 ELSE 4 END")
	}
	s.Where = strings.Join(wheres, " AND ")
	s.Rank = strings.Join(ranks, " + ")
	return s, true
}

// likeEscape takes % _ and \ literally in a LIKE pattern (ESCAPE '\').
func likeEscape(v string) string {
	return strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(v)
}
