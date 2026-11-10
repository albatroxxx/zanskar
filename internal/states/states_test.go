// SPDX-License-Identifier: Apache-2.0

package states

import (
	"errors"
	"strings"
	"testing"
)

// A lifecycle for the tests: a request that is decided once and may lapse.
func request() Lifecycle {
	return New("request", []string{"pending", "approved", "denied", "expired"},
		Move{From: "pending", To: "approved", By: "approve"},
		Move{From: "pending", To: "denied", By: "deny"},
		Move{From: "approved", To: "expired", By: "expiry"},
	)
}

// TestCheckNamesBothStates: a refused move says what the record is and what
// the move needs, in a sentence a person can act on (ADR 0047).
func TestCheckNamesBothStates(t *testing.T) {
	l := request()
	cases := []struct {
		from, to string
		want     string // "" for allowed
	}{
		{"pending", "approved", ""},
		{"pending", "denied", ""},
		{"approved", "expired", ""},
		{"denied", "approved", "the request is denied; only a pending request becomes approved"},
		{"expired", "approved", "the request is expired; only a pending request becomes approved"},
		{"pending", "pending", "the request is pending; nothing becomes pending"},
		{"approved", "approved", "the request is approved; only a pending request becomes approved"},
	}
	for _, c := range cases {
		err := l.Check(c.from, c.to)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s -> %s: unexpected %v", c.from, c.to, err)
			}
			continue
		}
		var se *Error
		if !errors.As(err, &se) {
			t.Fatalf("%s -> %s: want *Error, got %T", c.from, c.to, err)
		}
		if err.Error() != c.want {
			t.Errorf("%s -> %s:\n got %q\nwant %q", c.from, c.to, err.Error(), c.want)
		}
		if se.From != c.from || se.To != c.to || se.Lifecycle != "request" {
			t.Errorf("%s -> %s: error carries %+v", c.from, c.to, se)
		}
	}
}

// TestErrorJoinsSeveralFroms: when a state is reached from more than one,
// the refusal lists them all, once each, with "or".
func TestErrorJoinsSeveralFroms(t *testing.T) {
	l := New("grant", []string{"pending", "approved", "revoked"},
		Move{From: "pending", To: "revoked", By: "target deleted"},
		Move{From: "approved", To: "revoked", By: "revoke"},
		Move{From: "approved", To: "revoked", By: "target deleted"},
	)
	got := l.Check("revoked", "revoked").Error()
	want := "the grant is revoked; only a pending or approved grant becomes revoked"
	if got != want {
		t.Errorf("\n got %q\nwant %q", got, want)
	}
	if got := l.Next("approved"); len(got) != 1 || got[0] != "revoked" {
		t.Errorf("Next lists a state once: %v", got)
	}
	if got := New("thing", []string{"open", "ended"}, Move{From: "open", To: "ended", By: "end"}).Check("ended", "ended").Error(); !strings.Contains(got, "an open thing") {
		t.Errorf("article before a vowel: %q", got)
	}
}

// TestStatesAndMoves: the declaration answers the questions the guards and
// the document ask, and hands out copies.
func TestStatesAndMoves(t *testing.T) {
	l := request()
	if got := l.States(); strings.Join(got, ",") != "pending,approved,denied,expired" {
		t.Errorf("States: %v", got)
	}
	l.States()[0] = "x"
	if l.States()[0] != "pending" {
		t.Error("States handed out its own slice")
	}
	if !l.Has("denied") || l.Has("open") {
		t.Error("Has")
	}
	if !l.Can("pending", "approved") || l.Can("denied", "pending") {
		t.Error("Can")
	}
	if got := l.Next("pending"); strings.Join(got, ",") != "approved,denied" {
		t.Errorf("Next(pending) = %v", got)
	}
	if got := l.Next("denied"); len(got) != 0 {
		t.Errorf("Next(denied) = %v", got)
	}
	if len(l.Moves()) != 3 || l.Exposed() {
		t.Error("Moves or Exposed")
	}
	if got := Sorted([]string{"b", "a"}); got[0] != "a" {
		t.Errorf("Sorted: %v", got)
	}
}

// TestNewRefusesABrokenDeclaration: a move over an undeclared state, a state
// declared twice and a move with nothing making it all fail at init.
func TestNewRefusesABrokenDeclaration(t *testing.T) {
	cases := map[string]func(){
		"undeclared":  func() { New("x", []string{"a"}, Move{From: "a", To: "b", By: "go"}) },
		"twice":       func() { New("x", []string{"a", "a"}) },
		"empty state": func() { New("x", []string{""}) },
		"no by":       func() { New("x", []string{"a", "b"}, Move{From: "a", To: "b"}) },
	}
	for name, f := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
}

// TestMermaidAndMarkdown: the document shows the initial state, every move
// with what makes it, and the terminal states; an exposed lifecycle names its
// field and schemas, an unexposed one says so.
func TestMermaidAndMarkdown(t *testing.T) {
	l := request()
	l.Field, l.Schemas = "state", []string{"AccessRequest"}
	l.Derivation = "The stored status, except that an approval past its window reads expired."
	l.Notes = []string{"A pending request never expires."}
	got := l.Mermaid()
	for _, want := range []string{"stateDiagram-v2", "[*] --> pending", "pending --> approved: approve", "approved --> expired: expiry", "denied --> [*]", "expired --> [*]"} {
		if !strings.Contains(got, want) {
			t.Errorf("Mermaid lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "pending --> [*]") {
		t.Errorf("the initial state is not drawn as terminal:\n%s", got)
	}
	md := l.Markdown()
	for _, want := range []string{"## Request", "Field `state` on `AccessRequest`", "`pending`, `approved`, `denied`, `expired`", l.Derivation, "```mermaid", "- A pending request never expires."} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown lacks %q:\n%s", want, md)
		}
	}
	plain := New("connect flow", []string{"ticket issued", "live"}, Move{From: "ticket issued", To: "live", By: "upgrade"})
	if md := plain.Markdown(); !strings.Contains(md, "No API field carries it") || !strings.Contains(plain.Mermaid(), "ticket_issued --> live") {
		t.Errorf("unexposed lifecycle:\n%s\n%s", md, plain.Mermaid())
	}
}
