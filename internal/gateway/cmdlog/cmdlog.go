// SPDX-License-Identifier: Apache-2.0

// Package cmdlog turns a terminal session's keystrokes into the command lines
// a reviewer can list and search. The SSH and database bridges share it: a
// database session recorded no command line at all until 2026-11-11, so the
// SQL people ran could not be found.
package cmdlog

import (
	"bytes"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Log reconstructs the lines a user submits over a terminal and hands each
// one to mark, which records it as an asciicast marker. A reviewer can then
// list what was run without replaying the whole session.
//
// The gateway sees raw keystrokes and raw output, never the remote terminal's
// modes, so it cannot know directly whether input was echoed. It infers it: a
// submitted line is recorded verbatim only if that text appeared in the
// output since the line began. Text the remote did not echo, which is how a
// password prompt behaves, is recorded as "(hidden input)" and never stored.
type Log struct {
	mu    sync.Mutex
	line  []byte
	out   []byte
	esc   bool
	mark  func(string)
	delay time.Duration // how long after Enter to wait for the last echo
	// pending holds the submitted lines still waiting for their echo, so
	// Flush can record them when the session ends inside the wait.
	pending []*submitted
}

// submitted is one line between Enter and its marker; done makes sure it is
// recorded once, by its timer or by Flush, whichever comes first.
type submitted struct {
	text  string
	timer *time.Timer
	done  sync.Once
}

const (
	maxLine = 1024
	maxOut  = 16 << 10
)

func New(mark func(string)) *Log {
	return &Log{mark: mark, delay: 250 * time.Millisecond}
}

// Output feeds bytes the target sent to the browser.
func (c *Log) Output(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.out = append(c.out, data...)
	if len(c.out) > maxOut {
		c.out = c.out[len(c.out)-maxOut:]
	}
}

// Input feeds bytes the browser sent to the target.
func (c *Log) Input(data []byte) {
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
func (c *Log) submitLocked() {
	text := strings.TrimSpace(string(c.line))
	c.line = c.line[:0]
	if text == "" {
		return
	}
	s := &submitted{text: text}
	c.pending = append(c.pending, s)
	s.timer = time.AfterFunc(c.delay, func() { c.record(s) })
}

// record decides, once, whether a submitted line was echoed and marks it.
func (c *Log) record(s *submitted) {
	s.done.Do(func() {
		c.mu.Lock()
		echoed := bytes.Contains(c.out, []byte(s.text))
		for i, p := range c.pending {
			if p == s {
				c.pending = append(c.pending[:i], c.pending[i+1:]...)
				break
			}
		}
		// The echoes of lines still waiting are in the same output: it is
		// emptied once none is.
		if len(c.pending) == 0 {
			c.out = c.out[:0]
		}
		c.mu.Unlock()
		if !echoed {
			c.mark("(hidden input)")
			return
		}
		c.mark(clean(s.text))
	})
}

// Flush records the lines still waiting for their echo, with what has been
// echoed so far. A bridge calls it as the session ends, before the recording
// closes: the last statement before quitting was lost inside the wait
// (2026-11-11).
func (c *Log) Flush() {
	c.mu.Lock()
	waiting := append([]*submitted(nil), c.pending...)
	c.mu.Unlock()
	for _, s := range waiting {
		s.timer.Stop()
		c.record(s)
	}
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
