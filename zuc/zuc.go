package zuc

import (
	"fmt"

	gmsmCipher "github.com/emmansun/gmsm/cipher"
	gmsmZUC "github.com/emmansun/gmsm/zuc"
)

// validateZUCKey enforces the key-length contract shared by NewCipher/NewHash:
// 16 bytes (ZUC-128) or 32 bytes (ZUC-256). It returns the expected IV length
// for the detected variant so callers can validate the IV against the same key.
//
// Validating up front (rather than letting the underlying gmsm call fail) keeps
// the "zuc:" error prefix consistent across the package surface, so callers can
// branch on parameter mistakes without parsing gmsm's error strings.
func validateZUCKey(key []byte) (wantIV int, err error) {
	switch len(key) {
	case 16:
		return 16, nil
	case 32:
		return 23, nil
	default:
		return 0, fmt.Errorf("zuc: key length %d invalid (want 16 for ZUC-128 or 32 for ZUC-256)", len(key))
	}
}

// validateEEAKey enforces the 3GPP EEA3/EIA3 key contract: 16 bytes (ZUC-128).
// EEA3/EIA3 (3GPP TS 35.221) is a 128-bit algorithm; the 32-byte ZUC-256 key
// belongs to the NewCipher/NewHash generic path, not the 3GPP radio-bearer API.
func validateEEAKey(key []byte) error {
	if len(key) != 16 {
		return fmt.Errorf("zuc: 3GPP EEA/EIA key length %d invalid (want 16 for ZUC-128)", len(key))
	}
	return nil
}

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
	wantIV, err := validateZUCKey(key)
	if err != nil {
		return nil, err
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
	if err := validateEEAKey(key); err != nil {
		return nil, err
	}
	return gmsmZUC.NewEEACipher(key, count, bearer, direction)
}

// NewEIAHash creates a ZUC-EIA3 hash for 3GPP LTE integrity protection.
//
// SECURITY WARNING: The count field must be incremented for each frame to
// ensure a unique IV. Reusing the same (key, count, bearer, direction) tuple
// undermines integrity protection.
func NewEIAHash(key []byte, count, bearer, direction uint32) (EIA, error) {
	if err := validateEEAKey(key); err != nil {
		return nil, err
	}
	return gmsmZUC.NewEIAHash(key, count, bearer, direction)
}

// NewHash creates a ZUC-EIA hash with explicit key and IV.
func NewHash(key, iv []byte) (EIA, error) {
	wantIV, err := validateZUCKey(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != wantIV {
		return nil, fmt.Errorf("zuc: IV length %d invalid (want %d for %d-byte key)", len(iv), wantIV, len(key))
	}
	return gmsmZUC.NewHash(key, iv)
}

// Encrypt encrypts data using ZUC-EEA3 and returns the ciphertext.
func Encrypt(key []byte, count, bearer, direction uint32, plaintext []byte) ([]byte, error) {
	if err := validateEEAKey(key); err != nil {
		return nil, err
	}
	stream, err := gmsmZUC.NewEEACipher(key, count, bearer, direction)
	if err != nil {
		return nil, err
	}
	// Note: gmsmZUC.NewEEACipher returns a non-interface concrete type
	// boxed into the stream cipher interface; staticcheck proves (via
	// cross-package analysis) it never returns a nil interface. A defensive
	// `if stream == nil` check here is dead code (SA4023) and was removed.
	// If gmsm ever changes the contract, the XORKeyStream call below will
	// panic loudly rather than fail silently — which is the desired
	// failure mode for a contract regression.
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// MAC computes the ZUC-EIA3 message authentication code.
func MAC(key []byte, count, bearer, direction uint32, data []byte) ([]byte, error) {
	if err := validateEEAKey(key); err != nil {
		return nil, err
	}
	h, err := gmsmZUC.NewEIAHash(key, count, bearer, direction)
	if err != nil {
		return nil, err
	}
	// See Encrypt for why no defensive `if h == nil` check here:
	// gmsmZUC.NewEIAHash never returns a nil interface (SA4023).
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
