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
