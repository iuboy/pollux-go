package quicgm

import "fmt"

// PacketNumberLen is the on-wire length (1..4 octets) of a QUIC packet-number
// field. QUIC truncates the full 62-bit packet number to this width; the
// receiver reconstructs the full value from its largest acknowledged number
// (RFC 9000 §17.1).
type PacketNumberLen uint8

const (
	// PacketNumberLen1 is a 1-octet packet-number field.
	PacketNumberLen1 PacketNumberLen = 1
	// PacketNumberLen2 is a 2-octet packet-number field.
	PacketNumberLen2 PacketNumberLen = 2
	// PacketNumberLen3 is a 3-octet packet-number field.
	PacketNumberLen3 PacketNumberLen = 3
	// PacketNumberLen4 is a 4-octet packet-number field (always safe).
	PacketNumberLen4 PacketNumberLen = 4
)

// ChoosePacketNumberLen returns the smallest packet-number field width that
// lets the receiver reconstruct pn, given the largest packet number it has
// acknowledged (RFC 9000 §17.1). When largestAcked is nil (no feedback yet),
// it returns 4 octets, which is always decodable.
//
// The width is chosen so the gap (pn - largestAcked) fits within the
// reconstruction half-window 2^(8*n-1): 1 octet up to a gap of 127, 2 octets
// up to 32767, 3 up to 8388607, 4 up to 2^31-1. A larger gap cannot be
// encoded and signals the need for a key update.
func ChoosePacketNumberLen(pn uint64, largestAcked *uint64) (PacketNumberLen, error) {
	if largestAcked == nil {
		return PacketNumberLen4, nil
	}
	la := *largestAcked
	if pn <= la {
		return 0, fmt.Errorf("quicgm: packet number %d must exceed largest acknowledged %d", pn, la)
	}
	gap := pn - la
	switch {
	case gap < 1<<7:
		return PacketNumberLen1, nil
	case gap < 1<<15:
		return PacketNumberLen2, nil
	case gap < 1<<23:
		return PacketNumberLen3, nil
	case gap < 1<<31:
		return PacketNumberLen4, nil
	}
	return 0, fmt.Errorf("quicgm: packet number gap %d too large to encode; key update required", gap)
}

// TruncatePacketNumber returns the low n octets of pn, i.e. the value to place
// in the (header-protection-eligible) packet-number field on the wire.
func TruncatePacketNumber(pn uint64, n PacketNumberLen) uint64 {
	return pn & ((1 << (8 * uint64(n))) - 1)
}

// DecodePacketNumber reconstructs the full packet number from a truncated wire
// value, the largest packet number the receiver has acknowledged, and the
// on-wire width n (RFC 9000 §17.1 "Sample Packet Number Decoding Algorithm").
//
// Arithmetic is performed in int64 (packet numbers are < 2^62, well within
// range) to avoid uint64 underflow in the half-window comparisons.
func DecodePacketNumber(largestAcked, truncatedPN uint64, n PacketNumberLen) uint64 {
	pnNBits := int64(8 * uint64(n))
	pnWin := int64(1) << pnNBits
	pnHwin := pnWin >> 1
	pnMask := uint64(pnWin - 1)

	expected := int64(largestAcked) + 1
	candidateU := uint64(expected)&^pnMask | truncatedPN
	candidate := int64(candidateU)

	if candidate <= expected-pnHwin && candidateU+uint64(pnWin) < 1<<62 {
		return candidateU + uint64(pnWin)
	}
	if candidate > expected+pnHwin && candidate >= pnWin {
		return candidateU - uint64(pnWin)
	}
	return candidateU
}

// AppendPacketNumber appends pn truncated to n octets, big-endian, to b and
// returns the extended slice. This is the plaintext packet-number field before
// header protection is applied.
func AppendPacketNumber(b []byte, pn uint64, n PacketNumberLen) []byte {
	t := TruncatePacketNumber(pn, n)
	for i := int(n) - 1; i >= 0; i-- {
		b = append(b, byte(t>>(8*uint(i))))
	}
	return b
}
