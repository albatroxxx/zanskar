// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
	"testing"
	"time"
)

// TestLimiterRefusesNewKeysWhenFull: the sign-in limiter holds at most
// 65,536 keys, so a client spreading attempts over endless addresses cannot
// grow it without bound. When it is full, a new key is refused, which the
// sign-in answers with its ordinary 429, unless a sweep makes room; keys
// already held carry on (M10).
func TestLimiterRefusesNewKeysWhenFull(t *testing.T) {
	base := time.Now()
	now := base
	l := newIPLimiter(20, 10)
	l.now = func() time.Time { return now }
	const full = 1 << 16
	for i := 0; i < full; i++ {
		if !l.Allow(fmt.Sprintf("key-%d", i)) {
			t.Fatalf("key %d refused before the limiter was full", i)
		}
	}
	if l.Allow("newcomer") {
		t.Fatalf("a new key with %d keys held: admitted, want refused", full)
	}
	if !l.Allow("key-0") {
		t.Fatal("a key already held must still be served")
	}
	// Two seconds on no bucket has refilled, so a sweep frees nothing.
	now = base.Add(2 * time.Second)
	if l.Allow("newcomer") {
		t.Fatal("a new key while every bucket is still in use: admitted, want refused")
	}
	// A minute on every bucket is full again, the same as a new one, so the
	// sweep drops them and makes room.
	now = base.Add(time.Minute)
	if !l.Allow("newcomer") {
		t.Fatal("a new key once the buckets have refilled: refused, want admitted")
	}
}

// TestLimiterKey: IPv6 counts by /64, whatever the spelling; IPv4, IPv4
// written as IPv6, and anything unparseable count as they are (M10).
func TestLimiterKey(t *testing.T) {
	for in, want := range map[string]string{
		"2001:db8:1:2::1":                      "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff:ffff:ffff:ffff":     "2001:db8:1:2::/64",
		"2001:0DB8:0001:0002:0000:0000:0:0001": "2001:db8:1:2::/64",
		"[2001:db8:1:2::1]:443":                "2001:db8:1:2::/64",
		"fe80::1%eth0":                         "fe80::/64",
		"203.0.113.7":                          "203.0.113.7",
		"::ffff:203.0.113.7":                   "203.0.113.7",
		"not an address":                       "not an address",
	} {
		if got := limiterKey(in); got != want {
			t.Errorf("limiterKey(%q) = %q, want %q", in, got, want)
		}
	}
}
