package zuc

import (
	"fmt"

	gmsmCipher "github.com/emmansun/gmsm/cipher"
	gmsmZUC "github.com/emmansun/gmsm/zuc"
)

// SeekableStream is a stream cipher that supports seeking.
//
// Concurrency: SeekableStream values are NOT safe for concurrent use — the
// underlying gmsm stream cipher maintains an internal keystream buffer and
// counter that XORKeyStream and Seek mutate without synchronization, matching
// the standard library crypto/cipher.Stream contract. Callers sharing a
// stream across goroutines must serialize access; for parallel encryption,
// construct one stream per goroutine with an independent key/IV.
type SeekableStream = gmsmCipher.SeekableStream

// EIA represents a ZUC-based integrity/authentication hash.
//
// Concurrency: EIA values are NOT safe for concurrent use; Write/Sum mutate
// an internal MAC state. See SeekableStream's concurrency note.
type EIA = gmsmZUC.EIA

// NewCipher creates a ZUC stream cipher with the given key and IV.
// Key must be 16 bytes (ZUC-128) or 32 bytes (ZUC-256).
// IV must be 16 bytes (ZUC-128) or 23 bytes (ZUC-256), matching the key variant.
//
// Returns a typed error naming the offending parameter when key or IV length
// is invalid, so callers can distinguish a key-length mistake from an IV-
// length mistake without parsing the underlying gmsm error string.
//
// SECURITY WARNING: Reusing the same key+IV pair produces identical keystream,
// enabling XOR-based plaintext recovery (two-time pad attack). Each call must
// use a unique key/IV combination. See package documentation for details.
func NewCipher(key, iv []byte) (SeekableStream, error) {
	if len(key) != 16 && len(key) != 32 {
		return nil, fmt.Errorf("zuc: key length %d invalid (want 16 for ZUC-128 or 32 for ZUC-256)", len(key))
	}
	wantIV := 16
	if len(key) == 32 {
		wantIV = 23
	}
	if len(iv) != wantIV {
		return nil, fmt.Errorf("zuc: IV length %d invalid (want %d for %d-byte key)", len(iv), wantIV, len(key))
	}
	return gmsmZUC.NewCipher(key, iv)
}

// NewEEACipher creates a ZUC-EEA3 cipher for 3GPP LTE encryption.
// count is the frame counter, bearer is the radio bearer identity,
// direction is 0 for uplink and 1 for downlink.
//
// SECURITY WARNING: The count field must be incremented for each frame to
// ensure a unique IV. Reusing the same (key, count, bearer, direction) tuple
// produces identical keystream, enabling plaintext recovery.
func NewEEACipher(key []byte, count, bearer, direction uint32) (SeekableStream, error) {
	return gmsmZUC.NewEEACipher(key, count, bearer, direction)
}

// NewEIAHash creates a ZUC-EIA3 hash for 3GPP LTE integrity protection.
//
// SECURITY WARNING: The count field must be incremented for each frame to
// ensure a unique IV. Reusing the same (key, count, bearer, direction) tuple
// undermines integrity protection.
func NewEIAHash(key []byte, count, bearer, direction uint32) (EIA, error) {
	return gmsmZUC.NewEIAHash(key, count, bearer, direction)
}

// NewHash creates a ZUC-EIA hash with explicit key and IV.
func NewHash(key, iv []byte) (EIA, error) {
	return gmsmZUC.NewHash(key, iv)
}

// Encrypt encrypts data using ZUC-EEA3 and returns the ciphertext.
func Encrypt(key []byte, count, bearer, direction uint32, plaintext []byte) ([]byte, error) {
	stream, err := gmsmZUC.NewEEACipher(key, count, bearer, direction)
	if err != nil {
		return nil, err
	}
	if stream == nil {
		// Defensive: gmsm should never return (nil, nil), but a future
		// regression would panic on the XORKeyStream call below. Surface it
		// as an error instead.
		return nil, fmt.Errorf("zuc: NewEEACipher returned nil stream without error")
	}
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// MAC computes the ZUC-EIA3 message authentication code.
func MAC(key []byte, count, bearer, direction uint32, data []byte) ([]byte, error) {
	h, err := gmsmZUC.NewEIAHash(key, count, bearer, direction)
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, fmt.Errorf("zuc: NewEIAHash returned nil hash without error")
	}
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
