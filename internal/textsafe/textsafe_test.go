// SPDX-License-Identifier: Apache-2.0

package textsafe

import (
	"errors"
	"testing"
)

// u builds text from code points, so no invisible character sits in this
// source (see the package comment).
func u(parts ...any) string {
	var out []rune
	for _, p := range parts {
		switch v := p.(type) {
		case string:
			out = append(out, []rune(v)...)
		case int:
			out = append(out, rune(v))
		}
	}
	return string(out)
}

func TestName(t *testing.T) {
	for _, ok := range []string{
		"ops", "Prod SSH", "web-1.internal", "qa_walk", "Zurich-Buro", "<b>bold</b> & \"quotes\"",
		"",                                 // emptiness is each field's own rule
		u("Z", 0xFC, "rich-B", 0xFC, "ro"), // letters with diacritics
		u(0x6771, 0x4EAC),                  // CJK
		u(0x0928, 0x092E, 0x0938, 0x094D, 0x0924, 0x0947),                 // Devanagari
		u(0x0645, 0x06CC, 0x200C, 0x062E, 0x0648, 0x0627, 0x0647, 0x0645), // Persian with a zero-width non-joiner
		u(0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, " family"),           // an emoji sequence with joiners
		u(0x05E9, 0x05DC, 0x05D5, 0x05DD, 0x200F),                         // Hebrew with a right-to-left mark
	} {
		if err := Name(ok); err != nil {
			t.Errorf("Name(%q) = %v, want ok", ok, err)
		}
	}
	for label, c := range map[string]struct {
		s    string
		want error
	}{
		"bell":                   {u("bell", 0x07), ErrUnsafe},
		"newline":                {"two\nlines", ErrUnsafe},
		"tab":                    {"tab\there", ErrUnsafe},
		"nul":                    {u("nul", 0, "byte"), ErrUnsafe},
		"right-to-left override": {u("qa-bidi", 0x202E, "txt.exe"), ErrUnsafe},
		"isolates":               {u(0x2066, "isolate", 0x2069), ErrUnsafe},
		"zero-width space":       {u("zero", 0x200B, "width"), ErrUnsafe},
		"word joiner":            {u("word", 0x2060, "joiner"), ErrUnsafe},
		"byte-order mark":        {u(0xFEFF, "bom"), ErrUnsafe},
		"soft hyphen":            {u("soft", 0x00AD, "hyphen"), ErrUnsafe},
		"line separator":         {u("sep", 0x2028, "arator"), ErrUnsafe},
		"only zero-width":        {u(0x200B, 0x200B), ErrUnsafe},
		"spaces":                 {"   ", ErrInvisible},
		"only joiners":           {u(0x200D, 0x200C), ErrInvisible},
		"no-break spaces":        {u(" ", 0xA0, " "), ErrInvisible},
	} {
		if err := Name(c.s); !errors.Is(err, c.want) {
			t.Errorf("%s: Name(%q) = %v, want %v", label, c.s, err, c.want)
		}
	}
}

func TestTextAllowsLineBreaks(t *testing.T) {
	if err := Text("first line\r\nsecond\tcolumn"); err != nil {
		t.Errorf("Text with breaks: %v", err)
	}
	for _, s := range []string{u("bell", 7), u("over", 0x202E, "ride"), u("zero", 0x200B, "width"), u("nul", 0)} {
		if err := Text(s); !errors.Is(err, ErrUnsafe) {
			t.Errorf("Text(%q) = %v, want ErrUnsafe", s, err)
		}
	}
	if err := Text(" \n\t "); !errors.Is(err, ErrInvisible) {
		t.Errorf("Text of only whitespace: %v", err)
	}
}
