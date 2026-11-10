// SPDX-License-Identifier: Apache-2.0

// Package states declares a record's lifecycle in one place (ADR 0047): the
// states it can be in, the moves between them and what makes each move, and
// a refusal that names both states when a move is asked from the wrong one.
//
// A declaration is data. It does not route writes: the predicate in the SQL
// statement stays the real guard, and the declaration says what that
// predicate must be. Each domain package declares its lifecycle beside its
// types and writes one derivation, StateOf(row, now), pure over the struct;
// the handlers put its answer in the record's `state` field, the console
// shows it with the words in web/src/api/states.ts, and the guard tests in
// cmd/zanskar keep the declaration, the console labels, the OpenAPI enums
// and docs/lifecycles.md in step.
package states

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Move is one allowed transition. By names what makes it: an audit action
// where one is recorded, else the verb of the code path (the sweeper's
// "expiry", the clock's "time passes").
type Move struct {
	From, To, By string
}

// Lifecycle is one record's declared lifecycle.
type Lifecycle struct {
	// Name is the record, lower case, as the console label table and the
	// document key it: "session", "access request".
	Name string
	// Field is the JSON field that carries the computed state on the wire
	// ("state", "tls_status"), or "" for a lifecycle the document describes
	// but no API field exposes.
	Field string
	// Schemas are the OpenAPI schemas that carry Field, for the guard test.
	Schemas []string
	// Derivation says in a sentence or two how StateOf reads the state off
	// the row, for the document.
	Derivation string
	// Notes are facts a reader of the document needs that the diagram does
	// not carry: what is stored, what is only in memory, what is not yet
	// built.
	Notes []string

	states []string
	moves  []Move
}

// New declares a lifecycle with its states, in order (the first is the
// initial one), and its moves. It panics on a move naming an undeclared
// state or on a state declared twice: a declaration is checked when the
// package that holds it is initialised, so a mistake fails every test.
func New(name string, states []string, moves ...Move) Lifecycle {
	seen := map[string]bool{}
	for _, s := range states {
		if s == "" || seen[s] {
			panic(fmt.Sprintf("states: %s declares %q twice or empty", name, s))
		}
		seen[s] = true
	}
	for _, m := range moves {
		if !seen[m.From] || !seen[m.To] {
			panic(fmt.Sprintf("states: %s moves %q -> %q over an undeclared state", name, m.From, m.To))
		}
		if m.By == "" {
			panic(fmt.Sprintf("states: %s moves %q -> %q with nothing making it", name, m.From, m.To))
		}
	}
	return Lifecycle{Name: name, states: append([]string(nil), states...), moves: append([]Move(nil), moves...)}
}

// Doc is what the document and the guard tests need beyond the states and
// the moves; Describe attaches it.
type Doc struct {
	Field      string
	Schemas    []string
	Derivation string
	Notes      []string
}

// Describe returns the lifecycle with its documentation attached.
func (l Lifecycle) Describe(d Doc) Lifecycle {
	l.Field, l.Schemas, l.Derivation, l.Notes = d.Field, d.Schemas, d.Derivation, d.Notes
	return l
}

// States returns the declared states in declaration order.
func (l Lifecycle) States() []string { return append([]string(nil), l.states...) }

// Moves returns the declared moves in declaration order.
func (l Lifecycle) Moves() []Move { return append([]Move(nil), l.moves...) }

// Has reports whether s is a declared state.
func (l Lifecycle) Has(s string) bool { return slices.Contains(l.states, s) }

// Key is the lifecycle's name as the console label table and the document
// key it: lower case, underscores for spaces ("access request" is
// "access_request").
func (l Lifecycle) Key() string { return strings.ReplaceAll(strings.ToLower(l.Name), " ", "_") }

// Exposed reports whether an API field carries this lifecycle's state.
func (l Lifecycle) Exposed() bool { return l.Field != "" }

// Can reports whether a move from one state to another is declared.
func (l Lifecycle) Can(from, to string) bool {
	for _, m := range l.moves {
		if m.From == from && m.To == to {
			return true
		}
	}
	return false
}

// Next lists the states reachable from one, in declaration order of the
// moves, each once.
func (l Lifecycle) Next(from string) []string {
	var out []string
	for _, m := range l.moves {
		if m.From == from && !slices.Contains(out, m.To) {
			out = append(out, m.To)
		}
	}
	return out
}

// Check refuses a move that is not declared with an *Error that names the
// state the record is in and the states the move is allowed from. A declared
// move returns nil.
func (l Lifecycle) Check(from, to string) error {
	if l.Can(from, to) {
		return nil
	}
	var allowed []string
	for _, m := range l.moves {
		if m.To == to && !slices.Contains(allowed, m.From) {
			allowed = append(allowed, m.From)
		}
	}
	return &Error{Lifecycle: l.Name, From: from, To: to, Allowed: allowed}
}

// Error is a move asked from the wrong state. Handlers answer it with the
// conflict code the route already uses; its message is the sentence shown.
type Error struct {
	Lifecycle string
	From, To  string
	// Allowed are the states the move is declared from; empty when nothing
	// ever becomes To.
	Allowed []string
}

func (e *Error) Error() string {
	if len(e.Allowed) == 0 {
		return fmt.Sprintf("the %s is %s; nothing becomes %s", e.Lifecycle, e.From, e.To)
	}
	return fmt.Sprintf("the %s is %s; only %s %s %s becomes %s", e.Lifecycle, e.From, article(e.Allowed[0]), joinOr(e.Allowed), e.Lifecycle, e.To)
}

// Mermaid renders the lifecycle as a stateDiagram-v2, which GitHub draws
// inside Markdown, so docs/lifecycles.md shows the shape the code declares.
func (l Lifecycle) Mermaid() string {
	var b strings.Builder
	b.WriteString("stateDiagram-v2\n")
	if len(l.states) > 0 {
		fmt.Fprintf(&b, "    [*] --> %s\n", ident(l.states[0]))
	}
	for _, m := range l.moves {
		fmt.Fprintf(&b, "    %s --> %s: %s\n", ident(m.From), ident(m.To), m.By)
	}
	for _, s := range l.states {
		if len(l.Next(s)) == 0 && s != l.states[0] {
			fmt.Fprintf(&b, "    %s --> [*]\n", ident(s))
		}
	}
	return b.String()
}

// Markdown renders the lifecycle's section of docs/lifecycles.md: the
// field, the states, the derivation, the diagram and the notes.
func (l Lifecycle) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", strings.ToUpper(l.Name[:1])+l.Name[1:])
	if l.Exposed() {
		fmt.Fprintf(&b, "Field `%s` on %s. States: %s.\n\n", l.Field, joinCode(l.Schemas), joinCode(l.states))
	} else {
		fmt.Fprintf(&b, "No API field carries it. States: %s.\n\n", joinCode(l.states))
	}
	if l.Derivation != "" {
		b.WriteString(l.Derivation)
		b.WriteString("\n\n")
	}
	b.WriteString("```mermaid\n")
	b.WriteString(l.Mermaid())
	b.WriteString("```\n")
	for _, n := range l.Notes {
		fmt.Fprintf(&b, "\n- %s", n)
	}
	if len(l.Notes) > 0 {
		b.WriteString("\n")
	}
	return b.String()
}

// Sorted returns the states sorted, for comparisons that do not care about
// declaration order (the OpenAPI enum, the label table).
func Sorted(states []string) []string {
	out := append([]string(nil), states...)
	sort.Strings(out)
	return out
}

func joinOr(xs []string) string {
	switch len(xs) {
	case 0:
		return ""
	case 1:
		return xs[0]
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " or " + xs[len(xs)-1]
}

func joinCode(xs []string) string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = "`" + x + "`"
	}
	return strings.Join(out, ", ")
}

func article(word string) string {
	if word != "" && strings.ContainsRune("aeiou", rune(word[0])) {
		return "an"
	}
	return "a"
}

// ident makes a state usable as a Mermaid identifier: underscores are kept,
// spaces are not.
func ident(s string) string { return strings.ReplaceAll(s, " ", "_") }
