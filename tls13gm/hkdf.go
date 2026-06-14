package tls13gm

import (
	"fmt"

	"github.com/iuboy/pollux-go/sm3"
)

// HKDFExpandLabel implements TLS 1.3 HKDF-Expand-Label with SM3.
func HKDFExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	// RFC 8446: HkdfLabel.length is uint16 (0..65535).
	if length <= 0 || length > 65535 {
		return nil, fmt.Errorf("tls13gm: HKDFExpandLabel length must be 1..65535, got %d", length)
	}
	// RFC 5869 / HKDF constraint: HKDF-Expand output cannot exceed 255 × hashLen.
	// Provide a clear error here rather than letting the underlying sm3.HKDFExpand
	// return a generic "length too large" message.
	const maxHKDFExpandLen = 255 * sm3.Size // 255 × 32 = 8160
	if length > maxHKDFExpandLen {
		return nil, fmt.Errorf("tls13gm: HKDFExpandLabel length %d exceeds HKDF-Expand maximum of %d (255 × SM3 hash size)", length, maxHKDFExpandLen)
	}
	hkdfLabel, err := buildHKDFLabel(label, context, length)
	if err != nil {
		return nil, err
	}
	return sm3.HKDFExpand(secret, hkdfLabel, length)
}

func buildHKDFLabel(label string, context []byte, length int) ([]byte, error) {
	// RFC 8446 Section 7.1: HkdfLabel
	// length (2 bytes) + label length (1 byte) + "tls13 " + label + context length (1 byte) + context
	prefix := "tls13 "
	fullLabel := prefix + label
	// RFC 8446: opaque label<7..255> — "tls13 " is 6 bytes, so label must be at least 1 byte.
	// We don't enforce this at runtime since all callers use well-known labels, but the
	// fullLabel length must fit in one byte (≤255).
	if len(fullLabel) > 255 {
		return nil, fmt.Errorf("tls13gm: HKDF label too long: %d bytes (max 255)", len(fullLabel))
	}
	// RFC 8446 Section 7.1: opaque context<0..255> — context length must fit in one byte.
	if len(context) > 255 {
		return nil, fmt.Errorf("tls13gm: HKDF context too long: %d bytes (max 255)", len(context))
	}
	result := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	result = append(result, byte(length>>8), byte(length))
	result = append(result, byte(len(fullLabel)))
	result = append(result, fullLabel...)
	result = append(result, byte(len(context)))
	result = append(result, context...)
	return result, nil
}

// DeriveSecret implements TLS 1.3 Derive-Secret with SM3.
//
// transcriptHash MUST be the SM3 hash of the handshake transcript (i.e. a
// Transcript.Sum() snapshot, 32 bytes), NOT the raw transcript bytes. RFC 8446
// §7.1 defines Derive-Secret(secret, label, transcript) as
// HKDF-Expand-Label(secret, label, Hash(transcript), Hash.length); the hash is
// taken at the call site so it can be amortized via the incremental Transcript
// digest instead of re-hashing the full buffer each time.
func DeriveSecret(secret []byte, label string, transcriptHash []byte) ([]byte, error) {
	return HKDFExpandLabel(secret, label, transcriptHash, sm3.Size)
}
