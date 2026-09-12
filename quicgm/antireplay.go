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

// memoryAntiReplayCache is a process-local AntiReplayCache. It remembers each
// digest for `window`; attempts older than `maxAge` (typically the ticket
// lifetime) are rejected as expired.
//
// Eviction is bucketed by expiry time (byExpiry): only the buckets whose
// deadline has actually passed are dropped, so eviction costs O(expired
// entries) — amortized O(1) per Check — instead of a full O(n) map scan that
// would stall concurrent handshakes behind the mutex once per window.
type memoryAntiReplayCache struct {
	mu       sync.Mutex
	seen     map[string]int64   // digest -> expiry (unix nanos)
	byExpiry map[int64][]string // expiry bucket -> digests expiring then
	window   time.Duration
	maxAge   time.Duration
	now      func() time.Time
}

// NewAntiReplayCache returns a process-local anti-replay cache. window is how
// long a digest is remembered after first sight; maxAge is the maximum
// acceptable ticket age (reject older tickets as expired).
//
// Returns a rejecting cache (rejects all 0-RTT) if window or maxAge is non-
// positive, since a zero window would let the same digest be re-accepted
// indefinitely (exp.After(now) with a zero expiry is always false), breaking
// the anti-replay guarantee.
func NewAntiReplayCache(window, maxAge time.Duration) AntiReplayCache {
	if window <= 0 || maxAge <= 0 {
		return rejectingAntiReplayCache{}
	}
	return &memoryAntiReplayCache{
		seen:     make(map[string]int64),
		byExpiry: make(map[int64][]string),
		window:   window,
		maxAge:   maxAge,
		now:      time.Now,
	}
}

func (c *memoryAntiReplayCache) Check(digest []byte, age time.Duration) bool {
	// Reject at-or-beyond the max-age boundary (>=), not just beyond it (>).
	// RFC 8446 §8 requires the server to reject 0-RTT for an expired ticket;
	// using >= is the conservative choice and avoids accepting a ticket whose
	// age lands exactly on maxAge — where clock skew or rounding could let a
	// truly-expired ticket slip through.
	if age < 0 || age >= c.maxAge {
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
	nowN := now.UnixNano()
	// Lazy eviction: drop only the expiry buckets whose deadline has passed.
	// Each Check touches at most the expired buckets, never the live set.
	for expBucket, keys := range c.byExpiry {
		if expBucket <= nowN {
			for _, k := range keys {
				if c.seen[k] <= nowN {
					delete(c.seen, k)
				}
			}
			delete(c.byExpiry, expBucket)
		}
	}
	if exp, ok := c.seen[key]; ok && exp > nowN {
		return false // replayed within the window
	}
	exp := now.Add(c.window).UnixNano()
	c.seen[key] = exp
	c.byExpiry[exp] = append(c.byExpiry[exp], key)
	return true
}
