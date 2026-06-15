package quicgm

import (
	"crypto/rand"
	"errors"
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

// newTicketKeyRotator seeds the rotator. If seed is non-empty it is used as the
// initial current key (after a length check); otherwise a random key is
// generated. rotationPeriod is how often the current key is rotated.
func newTicketKeyRotator(seed []byte, rotationPeriod time.Duration) (*ticketKeyRotator, error) {
	if rotationPeriod <= 0 {
		return nil, errors.New("quicgm: ticket-key rotation period must be positive")
	}
	cur := make([]byte, tls13gm.SessionTicketKeyLen)
	if len(seed) >= tls13gm.SessionTicketKeyLen {
		copy(cur, seed[:tls13gm.SessionTicketKeyLen])
	} else if _, err := rand.Read(cur); err != nil {
		return nil, err
	}
	return &ticketKeyRotator{
		current:        cur,
		rotationPeriod: rotationPeriod,
		now:            time.Now,
	}, nil
}

// keys returns the active TEK list, newest first: [current, previous]. It
// performs a lazy rotation when the rotation period has elapsed (no background
// goroutine). The previous key is nil before the first rotation.
func (r *ticketKeyRotator) keys() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.now().Sub(r.rotatedAt) >= r.rotationPeriod {
		r.rotateLocked()
	}
	if r.previous == nil {
		return [][]byte{r.current}
	}
	return [][]byte{r.current, r.previous}
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
