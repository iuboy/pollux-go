package quicgm

import (
	"sync"
	"time"
)

// AntiReplayCache guards against 0-RTT replay attacks (RFC 8446 §8). A server
// that accepts 0-RTT MUST check every attempt against a cache; the default is
// fail-safe (reject all 0-RTT) so that, when no cache is configured, 0-RTT is
// refused rather than replayed.
//
// Multi-replica deployments must inject a shared implementation (Redis, etc.);
// the in-memory NewAntiReplayCache is single-process only.
type AntiReplayCache interface {
	// Check reports whether the 0-RTT attempt is fresh: the digest has not been
	// seen within the cache window and the ticket age is within the allowed
	// lifetime. It records the digest so a replay is rejected on the next call.
	Check(digest []byte, age time.Duration) bool
}

// rejectingAntiReplayCache rejects every 0-RTT attempt (fail-safe default).
type rejectingAntiReplayCache struct{}

func (rejectingAntiReplayCache) Check([]byte, time.Duration) bool { return false }

// memoryAntiReplayCache is a process-local AntiReplayCache backed by a map. It
// remembers each digest for `window`; attempts older than `maxAge` (typically
// the ticket lifetime) are rejected as expired.
type memoryAntiReplayCache struct {
	mu         sync.Mutex
	entries    map[string]time.Time // digest -> expiry
	window     time.Duration
	maxAge     time.Duration
	now        func() time.Time
	lastSweep  time.Time
	sweepEvery time.Duration
}

// NewAntiReplayCache returns a process-local anti-replay cache. window is how
// long a digest is remembered after first sight; maxAge is the maximum
// acceptable ticket age (reject older tickets as expired).
func NewAntiReplayCache(window, maxAge time.Duration) AntiReplayCache {
	return &memoryAntiReplayCache{
		entries:    make(map[string]time.Time),
		window:     window,
		maxAge:     maxAge,
		now:        time.Now,
		sweepEvery: window, // sweep at the same cadence as the replay window
	}
}

func (c *memoryAntiReplayCache) Check(digest []byte, age time.Duration) bool {
	if age < 0 || age > c.maxAge {
		return false // future or expired ticket
	}
	// An empty digest maps to the map key "" — every empty-digest attempt
	// would collide on that single key, so the first would be accepted and all
	// later ones (even from distinct legitimate connections) rejected as
	// replays. Reject empty digests outright: a valid 0-RTT attempt always
	// carries a non-empty (PSK-derived) digest.
	if len(digest) == 0 {
		return false
	}
	key := string(digest)
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	// Lazy eviction of expired entries to bound memory. Throttled by
	// sweepEvery so it isn't O(n) on every call.
	if c.lastSweep.IsZero() {
		c.lastSweep = now
	} else if c.lastSweep.Add(c.sweepEvery).Before(now) {
		for k, exp := range c.entries {
			if !exp.After(now) {
				delete(c.entries, k)
			}
		}
		c.lastSweep = now
	}
	if exp, ok := c.entries[key]; ok && exp.After(now) {
		return false // replayed within the window
	}
	c.entries[key] = now.Add(c.window)
	return true
}
