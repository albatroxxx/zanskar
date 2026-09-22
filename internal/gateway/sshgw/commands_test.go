// SPDX-License-Identifier: Apache-2.0

package sshgw

import (
	"sync"
	"testing"
	"time"
)

func newTestLog() (*commandLog, func() []string) {
	var mu sync.Mutex
	var got []string
	c := newCommandLog(func(s string) {
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
	c.input([]byte("ls -la"))
	c.output([]byte("ls -la")) // the remote echoes what was typed
	c.input([]byte("\r"))
	c.output([]byte("\r\ntotal 0\r\n$ "))
	if g := got(); len(g) != 1 || g[0] != "ls -la" {
		t.Fatalf("want [ls -la], got %v", g)
	}
}

func TestCommandLogHidesUnechoedInput(t *testing.T) {
	c, got := newTestLog()
	c.output([]byte("[sudo] password for ec2-user: "))
	c.input([]byte("hunter2\r")) // nothing comes back: echo is off
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
	c.input([]byte("lss\x7f"))
	c.input([]byte("\x1b[A"))
	c.output([]byte("lss\b \b"))
	c.input([]byte("\r"))
	if g := got(); len(g) != 1 || g[0] != "ls" {
		t.Fatalf("want [ls], got %v", g)
	}
}

func TestCommandLogIgnoresBlankAndAbandonedLines(t *testing.T) {
	c, got := newTestLog()
	c.input([]byte("\r\r"))
	c.input([]byte("rm -rf /\x03")) // Ctrl-C abandons the line
	c.input([]byte("\r"))
	if g := got(); len(g) != 0 {
		t.Fatalf("want nothing recorded, got %v", g)
	}
}
