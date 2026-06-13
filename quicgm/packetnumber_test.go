package quicgm

import (
	"testing"
)

// roundTrip verifies that a sender encoding pn (choosing width against
// largestAcked, then truncating) and a receiver decoding with the same
// largestAcked reconstruct the original pn.
func roundTrip(t *testing.T, pn uint64, largestAcked uint64) {
	t.Helper()
	n, err := ChoosePacketNumberLen(pn, &largestAcked)
	if err != nil {
		t.Fatalf("ChoosePacketNumberLen(%d, la=%d): %v", pn, largestAcked, err)
	}
	trunc := TruncatePacketNumber(pn, n)
	got := DecodePacketNumber(largestAcked, trunc, n)
	if got != pn {
		t.Errorf("round-trip pn=%d la=%d: width=%d trunc=%d decoded=%d", pn, largestAcked, n, trunc, got)
	}
}

func TestPacketNumber_ChooseNilAckedIsFour(t *testing.T) {
	n, err := ChoosePacketNumberLen(42, nil)
	if err != nil || n != PacketNumberLen4 {
		t.Fatalf("nil largestAcked => width 4, got %v %v", n, err)
	}
}

func TestPacketNumber_WidthThresholds(t *testing.T) {
	cases := []struct {
		gap   uint64
		wantN PacketNumberLen
	}{
		{1, PacketNumberLen1},
		{127, PacketNumberLen1}, // 2^7-1
		{128, PacketNumberLen2}, // 2^7
		{32767, PacketNumberLen2},
		{32768, PacketNumberLen3}, // 2^15
		{1<<23 - 1, PacketNumberLen3},
		{1 << 23, PacketNumberLen4},
		{1<<31 - 1, PacketNumberLen4},
	}
	for _, c := range cases {
		la := uint64(1_000_000)
		n, err := ChoosePacketNumberLen(la+c.gap, &la)
		if err != nil {
			t.Fatalf("gap %d: %v", c.gap, err)
		}
		if n != c.wantN {
			t.Errorf("gap %d: width got %d want %d", c.gap, n, c.wantN)
		}
	}
}

func TestPacketNumber_TooLargeGap(t *testing.T) {
	la := uint64(0)
	_, err := ChoosePacketNumberLen(1<<31, &la)
	if err == nil {
		t.Error("gap >= 2^31 should be an error (key update required)")
	}
}

func TestPacketNumber_PnNotGreaterThanAcked(t *testing.T) {
	la := uint64(10)
	if _, err := ChoosePacketNumberLen(10, &la); err == nil {
		t.Error("pn == la should error")
	}
	if _, err := ChoosePacketNumberLen(5, &la); err == nil {
		t.Error("pn < la should error")
	}
}

func TestPacketNumber_RoundTripBoundaryGaps(t *testing.T) {
	// For each width, the largest legal gap (2^(8n-1) - 1) and one past it
	// must round-trip at the boundary itself.
	for _, la := range []uint64{0, 1, 50, 1 << 20, 1 << 40} {
		for _, gap := range []uint64{
			1,
			1<<7 - 1, // last 1-octet gap
			1 << 7,   // first 2-octet gap
			1<<15 - 1,
			1 << 15,
			1<<23 - 1,
			1 << 23,
			1<<31 - 1, // last encodable gap
		} {
			roundTrip(t, la+gap, la)
		}
	}
}

func TestPacketNumber_DecodeMonotonicRun(t *testing.T) {
	// Simulate a connection: pn increments by 1 each packet, largest acked
	// lags behind. Every packet number must reconstruct regardless of width.
	la := uint64(1000)
	for pn := la + 1; pn < la+400; pn++ {
		roundTrip(t, pn, la)
	}
}

func TestPacketNumber_DecodeReconstructionBranches(t *testing.T) {
	// Truncated value equal to expected: returns it unchanged.
	if got := DecodePacketNumber(10, 11, PacketNumberLen1); got != 11 {
		t.Errorf("decode(la=10, trunc=11) = %d, want 11", got)
	}
	// Branch that pulls the value up into the next window: la=399, expected=400,
	// base=256. trunc=5 => candidate=261 <= 400-128=272, so return 261+256=517
	// (the candidate closest to expected).
	if got := DecodePacketNumber(399, 5, PacketNumberLen1); got != 517 {
		t.Errorf("decode(la=399, trunc=5) = %d, want 517", got)
	}
	// Round-trip the above against the chosen width to prove the pair is consistent.
	la := uint64(399)
	n, _ := ChoosePacketNumberLen(517, &la)
	if n != PacketNumberLen1 {
		t.Errorf("gap 118 should encode as 1 octet, got %d", n)
	}
	if got := DecodePacketNumber(la, TruncatePacketNumber(517, n), n); got != 517 {
		t.Errorf("round-trip 517: got %d", got)
	}
}

func TestPacketNumber_AppendRoundTripBigEndian(t *testing.T) {
	cases := []struct {
		pn uint64
		n  PacketNumberLen
	}{
		{0x00, PacketNumberLen1},
		{0xAB, PacketNumberLen1},
		{0x1234, PacketNumberLen2},
		{0x123456, PacketNumberLen3},
		{0x12345678, PacketNumberLen4},
	}
	for _, c := range cases {
		b := AppendPacketNumber(nil, c.pn, c.n)
		if len(b) != int(c.n) {
			t.Fatalf("pn=%#x n=%d: wrote %d bytes", c.pn, c.n, len(b))
		}
		got := decodePacketNumber(b) // reuse existing big-endian reader in packet.go
		if got != TruncatePacketNumber(c.pn, c.n) {
			t.Errorf("append/read %#x n=%d: got %#x", c.pn, c.n, got)
		}
	}
}
