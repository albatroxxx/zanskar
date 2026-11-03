// SPDX-License-Identifier: Apache-2.0

package recording

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"time"
)

// 2026-11-03, idea 5 (ADR 0041 amendment): what a terminal session printed is
// searched as well as what was typed. Output arrives as a terminal's byte
// stream: escape sequences for colour and the cursor, carriage returns that
// rewrite a line (a progress bar), backspaces. OutputLines reduces it to the
// lines a reader would recognise; screen-drawing programs (top, an editor)
// leave fragments, which the caps below bound.

// OutputLine is one line a session printed, at the time its first character
// arrived.
type OutputLine struct {
	At   time.Duration
	Text string
}

// MaxOutputLine bounds one indexed line, in bytes; a longer one is cut.
const MaxOutputLine = 2000

// Index reads an asciicast v2 stream once for both the command markers and
// up to maxLines lines of output (fewer than two visible characters, and a
// line the same as the one before, are left out), reporting whether more
// output was there than kept. maxLines 0 reads markers only.
func Index(r io.Reader, maxLines int) (markers []Marker, lines []OutputLine, truncated bool, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	b := lineBuilder{max: maxLines}
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 || line[0] != '[' {
			continue
		}
		var ev []json.RawMessage
		if err := json.Unmarshal(line, &ev); err != nil || len(ev) < 3 {
			continue
		}
		var kind string
		if err := json.Unmarshal(ev[1], &kind); err != nil || (kind != "m" && kind != "o") {
			continue
		}
		var at float64
		var data string
		if json.Unmarshal(ev[0], &at) != nil || json.Unmarshal(ev[2], &data) != nil {
			continue
		}
		when := time.Duration(at * float64(time.Second))
		if kind == "m" {
			markers = append(markers, Marker{At: when, Label: data})
		} else if maxLines > 0 {
			b.feed(when, data)
		}
	}
	b.end()
	return markers, b.out, b.truncated, sc.Err()
}

// OutputLines is Index's output alone.
func OutputLines(r io.Reader, maxLines int) ([]OutputLine, bool, error) {
	_, lines, truncated, err := Index(r, maxLines)
	return lines, truncated, err
}

// The escape-sequence states a terminal stream moves through.
const (
	stText    = iota
	stEsc     // after ESC
	stCSI     // ESC [ ... final byte
	stOSC     // ESC ] ... BEL or ESC \
	stOSCEsc  // ESC inside an OSC
	stCharset // ESC ( B and the like: one more character
)

// lineBuilder turns output, event by event, into lines; its state carries
// across events, which split lines and sequences anywhere.
type lineBuilder struct {
	max       int
	out       []OutputLine
	truncated bool

	state   int
	buf     []rune
	start   time.Duration
	pending bool // a carriage return waits to see whether a newline follows
	last    string
}

func (b *lineBuilder) feed(at time.Duration, data string) {
	for _, c := range data {
		if b.truncated {
			return
		}
		switch b.state {
		case stEsc:
			switch c {
			case '[':
				b.state = stCSI
			case ']':
				b.state = stOSC
			case '(', ')', '*', '+', '-', '.', '/', '#', '%':
				b.state = stCharset
			default:
				b.state = stText
			}
			continue
		case stCSI:
			if c >= 0x40 && c <= 0x7e {
				b.state = stText
			}
			continue
		case stOSC:
			switch c {
			case 0x07:
				b.state = stText
			case 0x1b:
				b.state = stOSCEsc
			}
			continue
		case stOSCEsc, stCharset:
			b.state = stText
			continue
		}
		if b.pending {
			b.pending = false
			if c != '\n' {
				// A lone carriage return: what follows writes over the line.
				b.buf = b.buf[:0]
			}
		}
		switch {
		case c == 0x1b:
			b.state = stEsc
		case c == '\n':
			b.flush()
		case c == '\r':
			b.pending = true
		case c == '\b':
			if n := len(b.buf); n > 0 {
				b.buf = b.buf[:n-1]
			}
		case c == '\t':
			b.put(at, ' ')
		case c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0):
			// Other control characters draw nothing.
		default:
			b.put(at, c)
		}
	}
}

// put adds a character to the line, noting the time of its first; a line
// past twice the indexed length grows no further (it is cut anyway).
func (b *lineBuilder) put(at time.Duration, c rune) {
	if len(b.buf) == 0 {
		b.start = at
	}
	if len(b.buf) < 2*MaxOutputLine {
		b.buf = append(b.buf, c)
	}
}

// flush keeps the line being built, if it says anything new.
func (b *lineBuilder) flush() {
	text := strings.TrimRight(string(b.buf), " ")
	b.buf = b.buf[:0]
	if visible(text) < 2 || text == b.last {
		return
	}
	if len(b.out) >= b.max {
		b.truncated = true
		return
	}
	if len(text) > MaxOutputLine {
		text = strings.ToValidUTF8(text[:MaxOutputLine], "")
	}
	b.last = text
	b.out = append(b.out, OutputLine{At: b.start, Text: text})
}

// end keeps a last line the stream did not finish with a newline.
func (b *lineBuilder) end() {
	if !b.truncated && len(b.buf) > 0 {
		b.flush()
	}
}

// visible counts the characters of s that are not spaces.
func visible(s string) int {
	n := 0
	for _, c := range s {
		if c != ' ' {
			n++
		}
	}
	return n
}
