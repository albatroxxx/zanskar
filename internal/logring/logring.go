// SPDX-License-Identifier: Apache-2.0

// Package logring keeps the gateway's most recent log records in memory so
// an administrator can read them in the console without journal access
// (QA finding R11). It wraps the real slog handler: every record still
// goes to stderr as before, and a copy of the last N is kept in a ring.
// Records carry no secrets by the project's logging rules, and the ring is
// admin-only and never persisted.
package logring

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Record is one log line as the console shows it.
type Record struct {
	Time  time.Time         `json:"time"`
	Level string            `json:"level"`
	Msg   string            `json:"msg"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// Ring holds the last Capacity records.
type Ring struct {
	mu   sync.Mutex
	buf  []Record
	next int
	full bool
	seen uint64
}

// New returns a ring for capacity records.
func New(capacity int) *Ring {
	if capacity <= 0 {
		capacity = 1000
	}
	return &Ring{buf: make([]Record, capacity)}
}

// Capacity is how many records the ring keeps.
func (r *Ring) Capacity() int { return len(r.buf) }

// Seen is how many records went through the ring since start.
func (r *Ring) Seen() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen
}

func (r *Ring) add(rec Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = rec
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
	r.seen++
}

// Snapshot returns, newest first, up to limit records at or above minLevel
// whose message or attributes contain q (case-insensitive; empty matches
// all).
func (r *Ring) Snapshot(minLevel slog.Level, q string, limit int) []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.next
	if r.full {
		n = len(r.buf)
	}
	q = strings.ToLower(strings.TrimSpace(q))
	// limit is a request parameter; the ring's capacity bounds it here so
	// the allocation cannot follow the caller.
	if limit <= 0 || limit > len(r.buf) {
		limit = len(r.buf)
	}
	out := make([]Record, 0, min(limit, n))
	for i := 1; i <= n && len(out) < limit; i++ {
		idx := (r.next - i + len(r.buf)) % len(r.buf)
		rec := r.buf[idx]
		if levelOf(rec.Level) < minLevel {
			continue
		}
		if q != "" && !matches(rec, q) {
			continue
		}
		out = append(out, rec)
	}
	return out
}

func matches(rec Record, q string) bool {
	if strings.Contains(strings.ToLower(rec.Msg), q) {
		return true
	}
	for k, v := range rec.Attrs {
		if strings.Contains(strings.ToLower(k), q) || strings.Contains(strings.ToLower(v), q) {
			return true
		}
	}
	return false
}

func levelOf(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo
	}
	return l
}

// Handler is a slog.Handler that records into the ring and forwards to
// the real handler. Attributes added with WithAttrs and groups opened with
// WithGroup are carried so the ring's copy matches what stderr shows.
type Handler struct {
	ring   *Ring
	base   slog.Handler
	attrs  map[string]string
	groups []string
}

// Wrap returns a handler recording into r and forwarding to base.
func (r *Ring) Wrap(base slog.Handler) *Handler { return &Handler{ring: r, base: base} }

// Enabled defers to the real handler, so the ring holds exactly what is
// logged at the current level.
func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool { return h.base.Enabled(ctx, l) }

// Handle records then forwards.
func (h *Handler) Handle(ctx context.Context, rec slog.Record) error {
	attrs := make(map[string]string, len(h.attrs)+rec.NumAttrs())
	for k, v := range h.attrs {
		attrs[k] = v
	}
	prefix := strings.Join(h.groups, ".")
	if prefix != "" {
		prefix += "."
	}
	rec.Attrs(func(a slog.Attr) bool {
		flatten(attrs, prefix, a)
		return true
	})
	h.ring.add(Record{Time: rec.Time.UTC(), Level: rec.Level.String(), Msg: rec.Message, Attrs: attrs})
	return h.base.Handle(ctx, rec)
}

func flatten(into map[string]string, prefix string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Value.Kind() == slog.KindGroup {
		for _, g := range a.Value.Group() {
			flatten(into, prefix+a.Key+".", g)
		}
		return
	}
	if a.Key == "" {
		return
	}
	into[prefix+a.Key] = a.Value.String()
}

// WithAttrs implements slog.Handler.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	n := &Handler{ring: h.ring, base: h.base.WithAttrs(attrs), attrs: make(map[string]string, len(h.attrs)+len(attrs)), groups: h.groups}
	for k, v := range h.attrs {
		n.attrs[k] = v
	}
	prefix := strings.Join(h.groups, ".")
	if prefix != "" {
		prefix += "."
	}
	for _, a := range attrs {
		flatten(n.attrs, prefix, a)
	}
	return n
}

// WithGroup implements slog.Handler.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &Handler{ring: h.ring, base: h.base.WithGroup(name), attrs: h.attrs, groups: append(append([]string(nil), h.groups...), name)}
}
