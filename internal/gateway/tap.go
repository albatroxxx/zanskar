// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"sync"
	"sync/atomic"
)

// replayBytes is how much recent output a Tap keeps so a watcher who joins
// mid-session sees the current screen rather than a blank one.
const replayBytes = 64 << 10

// Tap fans a live terminal session's output out to any number of watchers
// (auditors shadowing the session) and keeps a ring buffer of the most
// recent output for replay. Writes never block the session: a watcher that
// cannot keep up has chunks dropped and the drop counted.
type Tap struct {
	mu      sync.Mutex
	ring    []byte
	subs    map[uint64]chan []byte
	next    uint64
	closed  bool
	Dropped atomic.Int64
}

// NewTap returns an empty tap.
func NewTap() *Tap {
	return &Tap{subs: map[uint64]chan []byte{}}
}

// Write appends p to the ring and delivers a copy to every subscriber.
func (t *Tap) Write(p []byte) {
	if len(p) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.ring = append(t.ring, p...)
	if len(t.ring) > replayBytes {
		t.ring = t.ring[len(t.ring)-replayBytes:]
	}
	if len(t.subs) == 0 {
		return
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	for _, ch := range t.subs {
		select {
		case ch <- cp:
		default:
			t.Dropped.Add(1)
		}
	}
}

// Subscribe registers a watcher. replay holds the recent output at the time
// of subscription; ch delivers everything after it and is closed when the
// tap closes. cancel unsubscribes.
func (t *Tap) Subscribe() (ch <-chan []byte, replay []byte, cancel func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := make(chan []byte, 256)
	replay = make([]byte, len(t.ring))
	copy(replay, t.ring)
	if t.closed {
		close(c)
		return c, replay, func() {}
	}
	id := t.next
	t.next++
	t.subs[id] = c
	return c, replay, func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		if sub, ok := t.subs[id]; ok {
			delete(t.subs, id)
			close(sub)
		}
	}
}

// Watchers reports current subscribers.
func (t *Tap) Watchers() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.subs)
}

// Close ends the tap: every subscriber channel is closed and later writes
// are discarded.
func (t *Tap) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	for id, ch := range t.subs {
		delete(t.subs, id)
		close(ch)
	}
}
