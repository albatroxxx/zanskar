// SPDX-License-Identifier: Apache-2.0

package guac

import "testing"

// FuzzEncodeParse: anything Encode produces must Parse back to the same
// opcode and arguments, byte for byte, including invalid UTF-8 and the
// protocol's own delimiter characters inside values.
func FuzzEncodeParse(f *testing.F) {
	f.Add("select", "rdp", "")
	f.Add("size", "1920", "1080")
	f.Add("6.select,3.rdp;", ",", ".")
	f.Add("", "", "")
	f.Add("clipboard", "héllo wörld", "\xff\xfe")
	f.Fuzz(func(t *testing.T, op, a, b string) {
		raw := Encode(op, a, b)
		in, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(Encode(%q,%q,%q)) = %v", op, a, b, err)
		}
		if in.Opcode != op || len(in.Args) != 2 || in.Args[0] != a || in.Args[1] != b {
			t.Fatalf("round trip mismatch: %q -> %+v", raw, in)
		}
		if got := Opcode(raw); got != op {
			t.Fatalf("Opcode(%q) = %q, want %q", raw, got, op)
		}
		if in.String() != raw {
			t.Fatalf("String() not canonical: %q vs %q", in.String(), raw)
		}
	})
}

// FuzzParseRaw: arbitrary bytes must never panic, and anything that parses
// must re-encode to something that parses identically.
func FuzzParseRaw(f *testing.F) {
	f.Add("6.select,3.rdp;")
	f.Add("0.;")
	f.Add("1.a")
	f.Add("-1.a;")
	f.Add("99999999999999999999.a;")
	f.Add("3.abc,;")
	f.Fuzz(func(t *testing.T, raw string) {
		in, err := Parse(raw)
		if err != nil {
			return
		}
		again, err := Parse(in.String())
		if err != nil {
			t.Fatalf("re-parse of %q failed: %v", in.String(), err)
		}
		if again.Opcode != in.Opcode || len(again.Args) != len(in.Args) {
			t.Fatalf("re-parse mismatch: %+v vs %+v", again, in)
		}
		for i := range in.Args {
			if again.Args[i] != in.Args[i] {
				t.Fatalf("arg %d mismatch: %q vs %q", i, again.Args[i], in.Args[i])
			}
		}
	})
}
