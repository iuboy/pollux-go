package quicgm

import (
	"testing"
	"time"
)

func TestAntiReplayCache_RejectsReplay(t *testing.T) {
	c := NewAntiReplayCache(time.Minute, time.Hour)
	digest := []byte("ticket-digest")
	if !c.Check(digest, time.Second) {
		t.Fatal("fresh digest rejected")
	}
	if c.Check(digest, time.Second) {
		t.Fatal("replayed digest accepted")
	}
	// A different digest is still fresh.
	if !c.Check([]byte("other"), time.Second) {
		t.Fatal("second fresh digest rejected")
	}
}

func TestAntiReplayCache_RejectsBadAge(t *testing.T) {
	c := NewAntiReplayCache(time.Minute, time.Hour)
	if c.Check([]byte("d"), 2*time.Hour) {
		t.Fatal("expired ticket accepted")
	}
	if c.Check([]byte("d"), -time.Second) {
		t.Fatal("future ticket accepted")
	}
}

func TestRejectingAntiReplayCache(t *testing.T) {
	var c AntiReplayCache = rejectingAntiReplayCache{}
	if c.Check([]byte("d"), time.Second) {
		t.Fatal("rejecting cache accepted 0-RTT")
	}
}

// TestAntiReplayCache_RejectsEmptyDigest guards against the empty-digest
// collision: an empty (nil or zero-length) digest maps to the map key "" and
// would let the first empty-digest 0-RTT through while rejecting every later
// one as a replay. Empty digests must be rejected outright.
func TestAntiReplayCache_RejectsEmptyDigest(t *testing.T) {
	c := NewAntiReplayCache(time.Minute, time.Hour)
	if c.Check(nil, time.Second) {
		t.Fatal("nil digest should be rejected")
	}
	if c.Check([]byte{}, time.Second) {
		t.Fatal("empty digest should be rejected")
	}
	// A real (non-empty) digest after the rejected empty ones still works.
	if !c.Check([]byte("real-digest"), time.Second) {
		t.Fatal("non-empty digest rejected after empty ones")
	}
}
