package zuc

import (
	gmsmCipher "github.com/emmansun/gmsm/cipher"
	gmsmZUC "github.com/emmansun/gmsm/zuc"
)

// SeekableStream is a stream cipher that supports seeking.
type SeekableStream = gmsmCipher.SeekableStream

// EIA represents a ZUC-based integrity/authentication hash.
type EIA = gmsmZUC.EIA

// NewCipher creates a ZUC stream cipher with the given key and IV.
// Key must be 16 bytes (ZUC-128) or 32 bytes (ZUC-256).
// IV must be 16 bytes (ZUC-128) or 23 bytes (ZUC-256), matching the key variant;
// gmsm rejects a mismatched IV length.
//
// SECURITY WARNING: Reusing the same key+IV pair produces identical keystream,
// enabling XOR-based plaintext recovery (two-time pad attack). Each call must
// use a unique key/IV combination. See package documentation for details.
func NewCipher(key, iv []byte) (SeekableStream, error) {
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
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
