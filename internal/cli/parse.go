// SPDX-License-Identifier: Apache-2.0

// Package cli is the console's command line (ADR 0027): a fixed table of
// Zanskar commands, each turned into the API request the console itself would
// make and dispatched through the same router. It is never a shell: a line is
// a command name and its arguments, and nothing else is interpreted.
package cli

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

const (
	maxLine   = 1024
	maxTokens = 32
)

var (
	errEmpty    = errors.New("empty line")
	errTooLong  = fmt.Errorf("the line is longer than %d bytes", maxLine)
	errNotShell = errors.New("pipes, redirection, variables and command substitution are not supported: this is not a shell")
)

// shellChars are refused outside quotes. Nothing would interpret them, but
// refusing them says plainly that this is not a shell, instead of passing
// "a|b" on as a name that happens to contain a bar.
const shellChars = "|;&<>`$(){}\\"

// tokenize splits a line on spaces. Single or double quotes group words, with
// no escapes inside them. Control characters are refused.
func tokenize(line string) ([]string, error) {
	if len(line) > maxLine {
		return nil, errTooLong
	}
	var (
		tokens []string
		cur    strings.Builder
		inTok  bool
		quote  rune
	)
	flush := func() {
		if inTok {
			tokens = append(tokens, cur.String())
			cur.Reset()
			inTok = false
		}
	}
	for _, r := range line {
		if r == '\t' {
			r = ' '
		}
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return nil, errors.New("the line contains a control character")
		}
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
				continue
			}
			cur.WriteRune(r)
		case r == '"' || r == '\'':
			quote, inTok = r, true
		case r == ' ':
			flush()
		case strings.ContainsRune(shellChars, r):
			return nil, errNotShell
		default:
			cur.WriteRune(r)
			inTok = true
		}
	}
	if quote != 0 {
		return nil, errors.New("a quote is not closed")
	}
	flush()
	if len(tokens) == 0 {
		return nil, errEmpty
	}
	if len(tokens) > maxTokens {
		return nil, fmt.Errorf("more than %d words", maxTokens)
	}
	return tokens, nil
}

// parsed is a command line after the command name: positional arguments,
// free text after them, and flags.
type parsed struct {
	args  []string
	rest  string
	flags map[string]string
}

func (p parsed) flag(name string) string { return p.flags[name] }

func (p parsed) has(name string) bool { _, ok := p.flags[name]; return ok }

// parseArgs checks words against a command's arguments and flags.
func parseArgs(c *command, words []string) (parsed, error) {
	p := parsed{flags: map[string]string{}}
	var positional []string
	for i := 0; i < len(words); i++ {
		w := words[i]
		if !strings.HasPrefix(w, "--") || len(w) == 2 {
			positional = append(positional, w)
			continue
		}
		name, value, hasValue := strings.Cut(w[2:], "=")
		f := c.flagNamed(name)
		if f == nil {
			return p, fmt.Errorf("%s has no option --%s", c.name, name)
		}
		if _, dup := p.flags[name]; dup {
			return p, fmt.Errorf("--%s is given twice", name)
		}
		if f.value == "" {
			if hasValue {
				return p, fmt.Errorf("--%s takes no value", name)
			}
			p.flags[name] = ""
			continue
		}
		if !hasValue {
			if i+1 >= len(words) {
				return p, fmt.Errorf("--%s needs a value: --%s %s", name, name, f.value)
			}
			i++
			value = words[i]
		}
		if value == "" {
			return p, fmt.Errorf("--%s needs a value", name)
		}
		p.flags[name] = value
	}
	if len(positional) < len(c.args) {
		return p, fmt.Errorf("usage: %s", c.usage())
	}
	p.args = positional[:len(c.args)]
	extra := positional[len(c.args):]
	if len(extra) > 0 {
		if c.rest == "" {
			return p, fmt.Errorf("usage: %s", c.usage())
		}
		p.rest = strings.Join(extra, " ")
	}
	return p, nil
}

// nameRE is what an object name or id may look like before it is placed in an
// API path: no slashes, no query or fragment characters, nothing to traverse.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$`)

func checkName(kind, s string) error {
	if !nameRE.MatchString(s) {
		return fmt.Errorf("%q is not a valid %s", s, kind)
	}
	return nil
}
