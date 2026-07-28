package quicgm

import (
	"errors"
	"fmt"
)

// QUIC variable-length integer encoding per RFC 9000 §16.
//
// A varint is 1, 2, 4, or 8 octets. The two most-significant bits of the first
// octet encode the length:
//
//	0b00 -> 1 octet  (6 data bits,  max 63)
//	0b01 -> 2 octets (14 data bits, max 16383)
//	0b10 -> 4 octets (30 data bits, max 1073741823)
//	0b11 -> 8 octets (62 data bits, max 4611686018427387903)
const (
	// MaxVarint is the largest value representable as a QUIC varint (2^62 - 1).
	MaxVarint uint64 = 1<<62 - 1

	maxVarint1 uint64 = 63
	maxVarint2 uint64 = 16383
	maxVarint4 uint64 = 1073741823
)

// VarintLen returns the number of octets required to encode v as the smallest
// valid QUIC varint. It does not allocate.
func VarintLen(v uint64) int {
	switch {
	case v <= maxVarint1:
		return 1
	case v <= maxVarint2:
		return 2
	case v <= maxVarint4:
		return 4
	default:
		return 8
	}
}

// AppendVarint appends v to b as the smallest valid QUIC varint and returns the
// extended slice. Values above MaxVarint are rejected.
func AppendVarint(b []byte, v uint64) ([]byte, error) {
	if v > MaxVarint {
		return b, fmt.Errorf("quicgm: varint %d exceeds maximum %d", v, MaxVarint)
	}
	switch {
	case v <= maxVarint1:
		return append(b, byte(v)), nil
	case v <= maxVarint2:
		return append(b, byte(v>>8)|0x40, byte(v)), nil
	case v <= maxVarint4:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v)), nil
	default:
		return append(b,
			byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v)), nil
	}
}

// ReadVarint decodes a QUIC varint from the start of b. It returns the value
// and the number of octets consumed. It errors if b is empty or shorter than
// the encoded length.
func ReadVarint(b []byte) (value uint64, n int, err error) {
	if len(b) == 0 {
		return 0, 0, errors.New("quicgm: varint buffer is empty")
	}
	length := 1 << (b[0] >> 6) // 1, 2, 4, or 8
	if len(b) < length {
		return 0, 0, fmt.Errorf("quicgm: varint needs %d octets, buffer has %d", length, len(b))
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, length, nil
}
