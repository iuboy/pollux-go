package kdf

import (
	"errors"
	"fmt"
	"hash"

	xpbkdf2 "golang.org/x/crypto/pbkdf2"
)

// ErrInvalidIteration is returned when the iteration count is not positive.
var ErrInvalidIteration = errors.New("kdf: iteration count must be positive")

// ErrInvalidKeyLen is returned when the requested derived-key length is not
// positive. RFC 2898 permits any positive dkLen; the upper bound is enforced
// by the caller's hash output size times 2^32 - 1, which is far beyond any
// practical request.
var ErrInvalidKeyLen = errors.New("kdf: key length must be positive")

// maxIteration is a sanity upper bound on the iteration count. OWASP-recommended
// strengths (as of 2023) for PBKDF2-HMAC-SHA-256 are ≤ 1,000,000; we allow a
// generous margin above that while still rejecting attacker-controlled values
// that would stall the derivation loop (1<<30 ≈ 1.07e9 would take minutes).
const maxIteration = 10_000_000

// maxKeyLen is a sanity upper bound on the derived-key length. It exists to
// prevent the numBlocks*hLen capacity computation from overflowing int on
// 64-bit platforms when keyLen approaches MaxInt, which would panic in make.
// RFC 2898's theoretical ceiling of (2^32-1)*hLen is astronomically larger than
// any legitimate request.
const maxKeyLen = 1 << 20 // 1 MiB

// PBKDF2 derives a key of keyLen bytes from password and salt using PBKDF2
// (RFC 2898 / PKCS#5 v2.0 Section 5.2) with the given hash as the PRF.
//
// The derivation is delegated to golang.org/x/crypto/pbkdf2 (a vetted
// implementation); this wrapper preserves the package's input-validation
// boundary and (result, error) signature so callers — notably the pwhash
// package's pbkdf2-sm3 hasher — are unaffected.
//
// The hash factory h lets the caller pick the underlying PRF without binding
// this package to a specific hash:
//
//	dk, _ := PBKDF2(password, salt, 200_000, 32, sm3.New)      // GM
//	dk, _ := PBKDF2(password, salt, 600_000, 32, sha256.New)  // international
//
// Security notes:
//   - iter should be tuned to the target hash so that derivation takes
//     ~100ms on production hardware (the constant-time baseline for online
//     password verification). OWASP recommends ≥600,000 iterations for
//     PBKDF2-HMAC-SHA-256 as of 2023; 200,000 is comparable for SM3, which
//     is slower per iteration.
//   - salt should be unique per password; 16 random bytes is the typical
//     minimum.
//   - The returned slice is a fresh allocation; the caller may zero it via
//     memsecure.ZeroBytes when finished.
//
// iter and keyLen are bounded above to reject attacker-controlled pathological
// values (e.g. those parsed from untrusted PHC strings) that would otherwise
// cause CPU exhaustion. Both bounds are well above any legitimate use.
func PBKDF2(password, salt []byte, iter, keyLen int, h func() hash.Hash) ([]byte, error) {
	if iter <= 0 {
		return nil, ErrInvalidIteration
	}
	if iter > maxIteration {
		return nil, fmt.Errorf("kdf: iteration count %d exceeds limit %d: %w", iter, maxIteration, ErrInvalidIteration)
	}
	if keyLen <= 0 {
		return nil, ErrInvalidKeyLen
	}
	if keyLen > maxKeyLen {
		return nil, fmt.Errorf("kdf: key length %d exceeds limit %d: %w", keyLen, maxKeyLen, ErrInvalidKeyLen)
	}
	if h == nil {
		return nil, errors.New("kdf: hash factory must not be nil")
	}

	// golang.org/x/crypto/pbkdf2.Key signature matches exactly:
	// Key(password, salt, iter, keyLen, h func() hash.Hash) []byte
	return xpbkdf2.Key(password, salt, iter, keyLen, h), nil
}
