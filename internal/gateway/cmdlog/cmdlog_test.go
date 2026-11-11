// SPDX-License-Identifier: Apache-2.0

package cmdlog

import (
	"slices"
	"sync"
	"testing"
	"time"
)

func newTestLog() (*Log, func() []string) {
	var mu sync.Mutex
	var got []string
	c := New(func(s string) {
		mu.Lock()
		got = append(got, s)
		mu.Unlock()
	})
	c.delay = 5 * time.Millisecond
	return c, func() []string {
		time.Sleep(40 * time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

func TestCommandLogRecordsEchoedLines(t *testing.T) {
	c, got := newTestLog()
	c.Input([]byte("ls -la"))
	c.Output([]byte("ls -la")) // the remote echoes what was typed
	c.Input([]byte("\r"))
	c.Output([]byte("\r\ntotal 0\r\n$ "))
	if g := got(); len(g) != 1 || g[0] != "ls -la" {
		t.Fatalf("want [ls -la], got %v", g)
	}
}

func TestCommandLogHidesUnechoedInput(t *testing.T) {
	c, got := newTestLog()
	c.Output([]byte("[sudo] password for ec2-user: "))
	c.Input([]byte("hunter2\r")) // nothing comes back: echo is off
	if g := got(); len(g) != 1 || g[0] != "(hidden input)" {
		t.Fatalf("want [(hidden input)], got %v", g)
	}
	for _, s := range got() {
		if s == "hunter2" {
			t.Fatal("secret was recorded verbatim")
		}
	}
}

func TestCommandLogEditingAndEscapes(t *testing.T) {
	c, got := newTestLog()
	// "lss", backspace, then an up-arrow sequence that must be ignored.
	c.Input([]byte("lss\x7f"))
	c.Input([]byte("\x1b[A"))
	c.Output([]byte("lss\b \b"))
	c.Input([]byte("\r"))
	if g := got(); len(g) != 1 || g[0] != "ls" {
		t.Fatalf("want [ls], got %v", g)
	}
}

// recorder is a Log whose marks are kept, waiting an hour for each echo so
// only Flush records.
func recorder() (*Log, func() []string) {
	var got []string
	var mu sync.Mutex
	c := New(func(s string) { mu.Lock(); got = append(got, s); mu.Unlock() })
	c.delay = time.Hour
	return c, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), got...) }
}

// TestCommandLogFlushRecordsWaitingLines: a session that ends inside the wait
// for the echo still records its last line, once (2026-11-11: a statement run
// just before quitting was lost).
func TestCommandLogFlushRecordsWaitingLines(t *testing.T) {
	c, got := recorder()
	c.Input([]byte("SELECT 1;\r"))
	c.Output([]byte("SELECT 1;\r\n"))
	c.Flush()
	c.Flush() // a second flush records nothing again
	if want := []string{"SELECT 1;"}; !slices.Equal(got(), want) {
		t.Fatalf("got %q, want %q", got(), want)
	}
}

// TestCommandLogNeverTakesAnotherLinesOutputForAnEcho: a line's output is not
// another line's echo, even when both wait at once. Review, 2026-11-11: with
// the output kept for every waiting line, a secret typed at a prompt that
// does not echo matched what the line before printed and was recorded as
// itself.
func TestCommandLogNeverTakesAnotherLinesOutputForAnEcho(t *testing.T) {
	c, got := recorder()
	c.Input([]byte("echo hunter2\r"))
	c.Output([]byte("echo hunter2\r\nhunter2\r\n"))
	c.Input([]byte("hunter2\r")) // typed at a prompt that does not echo
	c.Flush()
	g := got()
	if slices.Contains(g, "hunter2") {
		t.Fatalf("a secret was recorded as itself: %q", g)
	}
	if want := []string{"echo hunter2", "(hidden input)"}; !slices.Equal(g, want) {
		t.Fatalf("got %q, want %q", g, want)
	}
}

func TestCommandLogIgnoresBlankAndAbandonedLines(t *testing.T) {
	c, got := newTestLog()
	c.Input([]byte("\r\r"))
	c.Input([]byte("rm -rf /\x03")) // Ctrl-C abandons the line
	c.Input([]byte("\r"))
	if g := got(); len(g) != 0 {
		t.Fatalf("want nothing recorded, got %v", g)
	}
}
