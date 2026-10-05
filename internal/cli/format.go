// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Line is one line of command output. Style tells the console how to colour
// it; the text itself never carries escape codes.
type Line struct {
	Text  string `json:"text"`
	Style string `json:"style,omitempty"` // "", head, ok, warn, error, muted
}

const (
	styleHead  = "head"
	styleOK    = "ok"
	styleWarn  = "warn"
	styleError = "error"
	styleMuted = "muted"
)

type out struct{ lines []Line }

func (o *out) add(style, format string, a ...any) {
	text := format
	if len(a) > 0 {
		text = fmt.Sprintf(format, a...)
	}
	for _, l := range strings.Split(text, "\n") {
		o.lines = append(o.lines, Line{Text: l, Style: style})
	}
}

func (o *out) text(format string, a ...any) { o.add("", format, a...) }

// maxCell keeps one long value (a reason, a log message) from pushing every
// other column off the screen.
const maxCell = 48

// table renders rows under a header line.
func (o *out) table(head []string, rows [][]string) {
	if len(rows) == 0 {
		o.add(styleMuted, "(none)")
		return
	}
	width := make([]int, len(head))
	for i, h := range head {
		width[i] = utf8.RuneCountInString(h)
	}
	for _, r := range rows {
		for i := range r {
			r[i] = clip(oneLine(r[i]), maxCell)
			if n := utf8.RuneCountInString(r[i]); n > width[i] {
				width[i] = n
			}
		}
	}
	render := func(cells []string) string {
		var b strings.Builder
		for i, c := range cells {
			b.WriteString(c)
			if i < len(cells)-1 {
				b.WriteString(strings.Repeat(" ", width[i]-utf8.RuneCountInString(c)+2))
			}
		}
		return strings.TrimRight(b.String(), " ")
	}
	o.add(styleHead, "%s", render(head))
	for _, r := range rows {
		o.text("%s", render(r))
	}
}

// pairs renders "key  value" lines with the keys aligned.
func (o *out) pairs(kv [][2]string) {
	w := 0
	for _, p := range kv {
		if n := len(p[0]); n > w {
			w = n
		}
	}
	for _, p := range kv {
		v := oneLine(p[1])
		if v == "" {
			v = "-"
		}
		o.text("%s%s  %s", p[0], strings.Repeat(" ", w-len(p[0])), v)
	}
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// ---- reading generic JSON

type obj = map[string]any

func str(m obj, key string) string {
	switch v := m[key].(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		if v {
			return "yes"
		}
		return "no"
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprintf("%d", int64(v))
		}
		return fmt.Sprintf("%g", v)
	case []any:
		parts := make([]string, 0, len(v))
		for _, x := range v {
			parts = append(parts, fmt.Sprint(x))
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+fmt.Sprint(v[k]))
		}
		return strings.Join(parts, " ")
	default:
		return fmt.Sprint(v)
	}
}

func num(m obj, key string) int64 {
	if f, ok := m[key].(float64); ok {
		return int64(f)
	}
	return 0
}

func sub(m obj, key string) obj {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return obj{}
}

// when renders an API timestamp as "2026-10-05 14:02 UTC".
func when(m obj, key string) string {
	s := str(m, key)
	if s == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return s
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// span renders a duration the way a person says it: 3d 4h, 28m, 40s.
func span(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
}

// short is the id prefix tables show; commands accept it back.
func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
