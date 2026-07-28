package quicgm

import "fmt"

// FrameTypeCrypto is the QUIC CRYPTO frame type (RFC 9000 §19.6).
const FrameTypeCrypto uint64 = 0x06

// AppendCryptoFrame appends a single QUIC CRYPTO frame carrying data at the
// given stream offset to b and returns the extended slice (RFC 9000 §19.6):
//
//	CRYPTO Frame {
//	  Type (i) = 0x06,
//	  Offset (i),
//	  Length (i),
//	  Crypto Data (..),
//	}
//
// offset and length are encoded as QUIC variable-length integers. CRYPTO frames
// carry TLS handshake messages at the Initial and Handshake encryption levels.
func AppendCryptoFrame(b []byte, offset uint64, data []byte) ([]byte, error) {
	b, err := AppendVarint(b, FrameTypeCrypto)
	if err != nil {
		return nil, err
	}
	b, err = AppendVarint(b, offset)
	if err != nil {
		return nil, err
	}
	b, err = AppendVarint(b, uint64(len(data)))
	if err != nil {
		return nil, err
	}
	return append(b, data...), nil
}

// ReadCryptoFrame parses one CRYPTO frame from the start of b, returning the
// stream offset, the crypto data, and the number of bytes consumed. It is the
// inverse of AppendCryptoFrame.
func ReadCryptoFrame(b []byte) (offset uint64, data []byte, n int, err error) {
	pos := 0
	ft, m, err := ReadVarint(b[pos:])
	if err != nil {
		return 0, nil, 0, fmt.Errorf("quicgm: read CRYPTO frame type: %w", err)
	}
	pos += m
	if ft != FrameTypeCrypto {
		return 0, nil, 0, fmt.Errorf("quicgm: not a CRYPTO frame (type %#x)", ft)
	}
	offset, m, err = ReadVarint(b[pos:])
	if err != nil {
		return 0, nil, 0, fmt.Errorf("quicgm: read CRYPTO offset: %w", err)
	}
	pos += m
	length, m, err := ReadVarint(b[pos:])
	if err != nil {
		return 0, nil, 0, fmt.Errorf("quicgm: read CRYPTO length: %w", err)
	}
	pos += m
	// Bounds-check in uint64 space to avoid int truncation on 32-bit platforms.
	remaining := uint64(len(b) - pos)
	if remaining < length {
		return 0, nil, 0, fmt.Errorf("quicgm: CRYPTO length %d exceeds remaining %d bytes", length, len(b)-pos)
	}
	end := pos + int(length)
	data = make([]byte, length)
	copy(data, b[pos:end])
	return offset, data, end, nil
}
