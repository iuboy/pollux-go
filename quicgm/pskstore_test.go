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
// AND that keys() returns that seed-derived key on its first call. Previously
// rotatedAt was the zero time, so keys() immediately rotated the seed away to
// a random key — breaking multi-replica determinism.
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
	// The seed-derived key must survive the first keys() call (the regression:
	// rotatedAt=zero used to rotate it away immediately).
	if got := r1.keys()[0]; !bytes.Equal(got, seed) {
		t.Errorf("first keys() call must return the seed-derived key, got %x want %x", got, seed)
	}
	if got := r2.keys()[0]; !bytes.Equal(got, seed) {
		t.Errorf("first keys() call must return the seed-derived key, got %x want %x", got, seed)
	}
}

// TestTicketKeyRotator_FirstCallDoesNotRotate is the focused regression guard
// for the rotatedAt=zero-time bug: the first keys() call (well within
// rotationPeriod of construction) must NOT rotate. We inject a controllable
// clock so the test is deterministic regardless of when it runs.
func TestTicketKeyRotator_FirstCallDoesNotRotate(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := start
	r, err := newTicketKeyRotator(nil, time.Hour)
	if err != nil {
		t.Fatalf("newTicketKeyRotator: %v", err)
	}
	r.now = func() time.Time { return now }
	original := r.current
	// Advance only 1 minute — far less than the 1-hour rotationPeriod.
	now = start.Add(time.Minute)
	got := r.keys()
	if len(got) != 1 || !bytes.Equal(got[0], original) {
		t.Fatalf("keys() at +%v should return the original key without rotating; got %d keys, original=%x", time.Minute, len(got), original)
	}
	if !bytes.Equal(r.current, original) {
		t.Fatal("keys() rotated the key within the rotation period (rotatedAt was not initialized)")
	}
}

// TestTicketKeyRotator_LongSeedTruncated confirms a seed longer than the key
// length is still accepted (first SessionTicketKeyLen bytes used), preserving
// the pre-existing len(seed) >= SessionTicketKeyLen behavior.
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
