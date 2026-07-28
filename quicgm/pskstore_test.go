package quicgm

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/tls13gm"
)

// TestTicketKeyRotator_ShortSeedRejected verifies that a non-empty but
// too-short seed is rejected with an error, instead of being silently
// replaced by a random key. The silent replacement was an availability hazard
// in multi-replica deployments: every replica passing the same short seed
// would end up with different random TEKs, so a ticket issued by one replica
// could not be decrypted by another.
func TestTicketKeyRotator_ShortSeedRejected(t *testing.T) {
	short := bytes.Repeat([]byte{0x01}, tls13gm.SessionTicketKeyLen-1) // 15 bytes
	if _, err := newTicketKeyRotator(short, time.Hour); err == nil {
		t.Fatal("expected error for short seed, got nil")
	} else if !strings.Contains(err.Error(), "session-ticket key seed") {
		t.Errorf("error should point at the short seed, got: %v", err)
	}
}

// TestTicketKeyRotator_EmptySeedOK confirms the empty-seed path still works
// (single-process default: fresh random key).
func TestTicketKeyRotator_EmptySeedOK(t *testing.T) {
	r, err := newTicketKeyRotator(nil, time.Hour)
	if err != nil {
		t.Fatalf("empty seed should succeed: %v", err)
	}
	if len(r.keys()[0]) != tls13gm.SessionTicketKeyLen {
		t.Errorf("current key len = %d, want %d", len(r.keys()[0]), tls13gm.SessionTicketKeyLen)
	}
}

// TestTicketKeyRotator_FullSeedDeterministic confirms that a full-length seed
// is used verbatim as the initial current TEK (deterministic across replicas)
// — the property the silent fallback previously broke. We read the rotator's
// initial `current` field directly because keys() performs a lazy rotation on
// first call (rotatedAt is the zero time), which is unrelated to seeding.
func TestTicketKeyRotator_FullSeedDeterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{0xA5}, tls13gm.SessionTicketKeyLen)
	r1, err := newTicketKeyRotator(seed, time.Hour)
	if err != nil {
		t.Fatalf("full seed: %v", err)
	}
	r2, err := newTicketKeyRotator(seed, time.Hour)
	if err != nil {
		t.Fatalf("full seed: %v", err)
	}
	if !bytes.Equal(r1.current, seed) {
		t.Errorf("current TEK must equal the seed before any rotation: got %x", r1.current)
	}
	if !bytes.Equal(r1.current, r2.current) {
		t.Error("same full-length seed must produce identical initial current TEKs (multi-replica determinism)")
	}
}

// TestTicketKeyRotator_LongSeedTruncated confirms a seed longer than the key
// length is still accepted (first SessionTicketKeyLen bytes used), preserving
// the pre-existing len(seed) >= SessionTicketKeyLen behavior. Reads the
// initial current field (see FullSeedDeterministic for why not keys()).
func TestTicketKeyRotator_LongSeedTruncated(t *testing.T) {
	seed := bytes.Repeat([]byte{0xB9}, tls13gm.SessionTicketKeyLen+5) // 21 bytes
	r, err := newTicketKeyRotator(seed, time.Hour)
	if err != nil {
		t.Fatalf("long seed should succeed: %v", err)
	}
	if !bytes.Equal(r.current, seed[:tls13gm.SessionTicketKeyLen]) {
		t.Error("long seed should be truncated to the first SessionTicketKeyLen bytes as the initial current key")
	}
}
