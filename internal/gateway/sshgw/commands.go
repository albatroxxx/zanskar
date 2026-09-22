// SPDX-License-Identifier: Apache-2.0

package sshgw

import (
	"bytes"
	"strings"
	"sync"
	"time"
	"unicode"
)

// commandLog reconstructs the lines a user submits over an SSH terminal and
// hands each one to mark, which records it as an asciicast marker. A reviewer
// can then list what was run without replaying the whole session.
//
// The gateway sees raw keystrokes and raw output, never the remote terminal's
// modes, so it cannot know directly whether input was echoed. It infers it: a
// submitted line is recorded verbatim only if that text appeared in the
// output since the line began. Text the remote did not echo, which is how a
// password prompt behaves, is recorded as "(hidden input)" and never stored.
type commandLog struct {
	mu    sync.Mutex
	line  []byte
	out   []byte
	esc   bool
	mark  func(string)
	delay time.Duration // how long after Enter to wait for the last echo
}

const (
	maxLine = 1024
	maxOut  = 16 << 10
)

func newCommandLog(mark func(string)) *commandLog {
	return &commandLog{mark: mark, delay: 250 * time.Millisecond}
}

// output feeds bytes the target sent to the browser.
func (c *commandLog) output(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.out = append(c.out, data...)
	if len(c.out) > maxOut {
		c.out = c.out[len(c.out)-maxOut:]
	}
}

// input feeds bytes the browser sent to the target.
func (c *commandLog) input(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, b := range data {
		if c.esc {
			// Drop the rest of an escape sequence (arrow keys, function keys):
			// CSI parameters then a final byte in the 0x40-0x7e range.
			if b >= 0x40 && b <= 0x7e && b != '[' {
				c.esc = false
			}
			continue
		}
		switch {
		case b == '\r' || b == '\n':
			c.submitLocked()
		case b == 0x7f || b == 0x08:
			if n := len(c.line); n > 0 {
				c.line = c.line[:n-1]
			}
		case b == 0x03 || b == 0x15: // Ctrl-C, Ctrl-U abandon the line
			c.line = c.line[:0]
		case b == 0x1b:
			c.esc = true
		case b == '\t' || b < 0x20:
			// Tab completion changes the text on screen, not what was typed;
			// other control bytes carry nothing to record.
		default:
			if len(c.line) < maxLine {
				c.line = append(c.line, b)
			}
		}
	}
}

// submitLocked takes the current line and decides, after a short wait for the
// last echo to arrive, whether it may be recorded verbatim.
func (c *commandLog) submitLocked() {
	text := strings.TrimSpace(string(c.line))
	c.line = c.line[:0]
	if text == "" {
		return
	}
	time.AfterFunc(c.delay, func() {
		c.mu.Lock()
		echoed := bytes.Contains(c.out, []byte(text))
		c.out = c.out[:0]
		c.mu.Unlock()
		if !echoed {
			c.mark("(hidden input)")
			return
		}
		c.mark(clean(text))
	})
}

// clean drops control characters and caps the label; markers are labels on a
// timeline, not a transcript.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if len(s) > 512 {
		s = s[:512] + "…"
	}
	return s
}
