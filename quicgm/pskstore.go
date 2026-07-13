package quicgm

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/iuboy/pollux-go/tls13gm"
)

// ticketKeyRotator is a process-local manager for the stateless session-ticket
// encryption keys (TEKs). It keeps the current and previous TEK and rotates the
// current one on a fixed cadence (RFC 8446 §4.6.1 recommends rotating at
// ticket_lifetime/2). Tickets are encrypted under the current key and decrypt
// tries current then previous, so a ticket issued just before a rotation stays
// valid across the rotation window.
//
// Single-process: the keys live in memory. Multi-replica deployments must share
// the seed (ServerConfig.SessionTicketKey) and synchronize rotation externally.
type ticketKeyRotator struct {
	mu             sync.Mutex
	current        []byte
	previous       []byte
	rotatedAt      time.Time
	rotationPeriod time.Duration
	now            func() time.Time
}

// newTicketKeyRotator seeds the rotator. If seed is non-empty it MUST be at
// least SessionTicketKeyLen bytes; the first SessionTicketKeyLen bytes are used
// as the initial current key. An empty seed generates a fresh random key
// (single-process default). A non-empty but short seed is rejected rather than
// silently replaced: in a multi-replica deployment every replica must derive
// the same TEK from the same seed, so quietly substituting a random key on a
// short seed would make tickets issued by one replica undecryptable by another.
func newTicketKeyRotator(seed []byte, rotationPeriod time.Duration) (*ticketKeyRotator, error) {
	if rotationPeriod <= 0 {
		return nil, errors.New("quicgm: ticket-key rotation period must be positive")
	}
	cur := make([]byte, tls13gm.SessionTicketKeyLen)
	if len(seed) > 0 {
		if len(seed) < tls13gm.SessionTicketKeyLen {
			return nil, fmt.Errorf("quicgm: session-ticket key seed must be at least %d bytes, got %d",
				tls13gm.SessionTicketKeyLen, len(seed))
		}
		copy(cur, seed[:tls13gm.SessionTicketKeyLen])
	} else if _, err := rand.Read(cur); err != nil {
		return nil, err
	}
	nowFn := time.Now
	return &ticketKeyRotator{
		current:        cur,
		rotationPeriod: rotationPeriod,
		// Mark the seed-derived key as freshly rotated so the first keys() call
		// does NOT immediately rotate it away. The zero value of time.Time
		// (0001-01-01) would make now().Sub(rotatedAt) span ~2025 years,
		// exceeding any rotationPeriod and discarding the seed on first use —
		// breaking multi-replica determinism (every replica would independently
		// rotate to a different random key).
		rotatedAt: nowFn(),
		now:       nowFn,
	}, nil
}

// keys returns the active TEK list, newest first: [current, previous]. It
// performs a lazy rotation when the rotation period has elapsed (no background
// goroutine). The previous key is nil before the first rotation.
//
// Returns defensive copies so callers cannot mutate the rotator's internal key
// material through the returned slices.
func (r *ticketKeyRotator) keys() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.now().Sub(r.rotatedAt) >= r.rotationPeriod {
		r.rotateLocked()
	}
	cur := make([]byte, len(r.current))
	copy(cur, r.current)
	if r.previous == nil {
		return [][]byte{cur}
	}
	prev := make([]byte, len(r.previous))
	copy(prev, r.previous)
	return [][]byte{cur, prev}
}

// rotateLocked forces a rotation: previous <- current, current <- fresh random.
// Used by tests to exercise the rotation window deterministically.
func (r *ticketKeyRotator) rotateLocked() {
	next := make([]byte, tls13gm.SessionTicketKeyLen)
	if _, err := rand.Read(next); err != nil {
		return // keep current key on failure; next keys() call retries
	}
	r.previous = r.current
	r.current = next
	r.rotatedAt = r.now()
}

// rotate forces an immediate rotation (test/diagnostics helper).
func (r *ticketKeyRotator) rotate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rotateLocked()
}
