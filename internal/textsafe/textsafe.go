// SPDX-License-Identifier: Apache-2.0

// Package textsafe checks the text a person types as a name, so that a name
// cannot read as something it is not in a list, a policy picker or an audit
// sentence (2026-11-04, live walkthrough of 1.18.4: a group named with a
// right-to-left override showed as a different file name, one with a
// zero-width space as a twin of another, and one of only zero-width spaces as
// a blank row). It refuses what no name needs, and keeps what some scripts do:
// the zero-width joiner and non-joiner, which Persian, Indic scripts and emoji
// sequences use, and the left-to-right and right-to-left marks.
//
// The code points are written as numbers on purpose: an invisible character in
// this file's source would be the very thing it exists to keep out.
package textsafe

import (
	"errors"
	"unicode"
)

// ErrUnsafe is returned for text that holds a character a name must not.
var ErrUnsafe = errors.New("must not contain control, direction-override or zero-width characters")

// ErrInvisible is returned for text with nothing to see in it.
var ErrInvisible = errors.New("must contain a visible character")

// Name checks single-line text: a name, a label. No control characters at all
// (a newline included), so it cannot break a line of a log or a CSV row.
func Name(s string) error { return check(s, false) }

// Text checks free text such as a description or notes: line breaks and tabs
// are allowed, every other control character is not.
func Text(s string) error { return check(s, true) }

func check(s string, multiline bool) error {
	visible := false
	for _, r := range s {
		switch {
		case r == 0x0A || r == 0x0D || r == 0x09: // line feed, carriage return, tab
			if !multiline {
				return ErrUnsafe
			}
		case unicode.IsControl(r), unsafeFormat(r), r == 0x2028, r == 0x2029:
			return ErrUnsafe
		case !unicode.IsSpace(r) && !unicode.Is(unicode.Cf, r):
			visible = true
		}
	}
	if !visible && s != "" {
		return ErrInvisible
	}
	return nil
}

// unsafeFormat is a format character that changes how text is laid out or
// hides in it: the bidirectional embeddings, overrides and isolates, the
// zero-width space, the word joiner, the byte-order mark, the soft hyphen and
// the invisible operators. The joiners and the directional marks are not
// among them.
func unsafeFormat(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E: // LRE RLE PDF LRO RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI RLI FSI PDI
		return true
	case r >= 0x2061 && r <= 0x2064: // invisible operators
		return true
	case r == 0x200B, r == 0x2060, r == 0xFEFF, r == 0x00AD: // ZWSP, WJ, BOM, soft hyphen
		return true
	}
	return false
}
