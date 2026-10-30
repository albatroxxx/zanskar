// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"runtime"
	"sync"
	"time"
)

// maxLimiterKeys bounds how many keys an ipLimiter holds. Whoever controls
// many addresses (an IPv6 /48 alone holds 65,536 /64s) could otherwise grow
// its map without limit.
const maxLimiterKeys = 1 << 16

// ipLimiter is a token bucket per key (client address, session id). It bounds
// online guessing independently of the per-account lockout, so an attacker
// spraying many accounts from one address is slowed as well.
type ipLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	rate      float64 // tokens per second
	burst     float64
	maxKeys   int
	lastGC    time.Time
	lastSweep time.Time // the last sweep a full map forced
	now       func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
	// refusing is set by a refusal and cleared when a token is taken, so
	// Take can tell the first refusal of a run from the rest.
	refusing bool
}

func newIPLimiter(perMinute, burst int) *ipLimiter {
	return &ipLimiter{
		buckets: map[string]*bucket{},
		rate:    float64(perMinute) / 60,
		burst:   float64(burst),
		maxKeys: maxLimiterKeys,
		now:     time.Now,
		lastGC:  time.Now(),
	}
}

// Allow consumes one token for key if available. A new key that finds the
// limiter full is refused the same way, unless a sweep makes room for it.
func (l *ipLimiter) Allow(key string) bool {
	ok, _ := l.Take(key)
	return ok
}

// Take is Allow that also reports whether a refusal is the first of a run
// for key, the one worth recording: the rest of the run says nothing new. A
// new key refused because the limiter is full holds no bucket to remember
// the run by, so its refusals are never first.
func (l *ipLimiter) Take(key string) (ok, firstRefusal bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.lastGC) > 10*time.Minute {
		l.sweep(now)
		l.lastGC = now
	}
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			// At most one forced sweep a second: each walks the whole map
			// under the lock, and a flood of new keys must not make every
			// attempt pay for one.
			if now.Sub(l.lastSweep) >= time.Second {
				l.sweep(now)
				l.lastSweep = now
			}
			if len(l.buckets) >= l.maxKeys {
				return false, false
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		first := !b.refusing
		b.refusing = true
		return false, first
	}
	b.tokens--
	b.refusing = false
	return true, false
}

// sweep drops the buckets that have refilled to the burst. Such a bucket
// behaves exactly as a new one would, so forgetting it changes nothing.
func (l *ipLimiter) sweep(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}

// limiterKey is the key the sign-in limiter counts an address under: an
// IPv4 address as it is, an IPv6 address by its /64. One IPv6 client
// usually holds a whole /64 and can use any address in it, so counting
// addresses one by one would hand it 2^64 fresh buckets. Anything that does
// not parse is used as it is.
func limiterKey(ip string) string {
	addr, ok := parseAddr(ip)
	if !ok {
		return ip
	}
	addr = addr.WithZone("")
	if addr.Is4() {
		return addr.String()
	}
	p, err := addr.Prefix(64)
	if err != nil {
		return ip
	}
	return p.String()
}

// hashWait is how long a password check waits for a free slot before the
// request is answered 503 busy.
const hashWait = 5 * time.Second

// hashGate bounds how many password hashes run at once. Each Argon2id check
// takes 64 MiB and about 100 ms of a core, and every sign-in attempt runs
// one, unknown usernames included, by design (user.BurnPasswordCheck). The
// per-address limiter does not bound how many addresses try at once: a
// hundred of them each spending its burst asks for gigabytes at the same
// moment, and the out-of-memory kill that follows ends every live session.
type hashGate struct {
	slots chan struct{}
	wait  time.Duration
}

func newHashGate(slots int, wait time.Duration) *hashGate {
	return &hashGate{slots: make(chan struct{}, slots), wait: wait}
}

// passwordHashing is the gate every password check on the sign-in paths
// goes through. It is shared, as the memory and cores it guards are.
var passwordHashing = newHashGate(max(2, runtime.NumCPU()), hashWait)

// enter takes a slot, waiting up to the gate's wait or until ctx ends, and
// returns the function that gives it back. ok is false when no slot came
// free.
func (g *hashGate) enter(ctx context.Context) (leave func(), ok bool) {
	select {
	case g.slots <- struct{}{}:
		return g.leave, true
	default:
	}
	t := time.NewTimer(g.wait)
	defer t.Stop()
	select {
	case g.slots <- struct{}{}:
		return g.leave, true
	case <-t.C:
	case <-ctx.Done():
	}
	return nil, false
}

func (g *hashGate) leave() { <-g.slots }

// IPLimiter is the per-address token bucket the sign-in routes use, for
// other machine-facing routes that take a secret (the SCIM endpoint).
type IPLimiter = ipLimiter

// NewIPLimiter allows perMinute requests per address after a burst.
func NewIPLimiter(perMinute, burst int) *IPLimiter { return newIPLimiter(perMinute, burst) }

// LimiterKey is the bucket an address counts against: an IPv4 address as
// it is, an IPv6 address by its /64.
func LimiterKey(ip string) string { return limiterKey(ip) }
