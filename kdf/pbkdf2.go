package kdf

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"hash"
)

// ErrInvalidIteration is returned when the iteration count is not positive.
var ErrInvalidIteration = errors.New("kdf: iteration count must be positive")

// ErrInvalidKeyLen is returned when the requested derived-key length is not
// positive. RFC 2898 permits any positive dkLen; the upper bound is enforced
// by the caller's hash output size times 2^32 - 1, which is far beyond any
// practical request.
var ErrInvalidKeyLen = errors.New("kdf: key length must be positive")

// PBKDF2 derives a key of keyLen bytes from password and salt using PBKDF2
// (RFC 2898 / PKCS#5 v2.0 Section 5.2) with the given hash as the PRF.
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
//     password verification). For SM3 / SHA-256, 100k–600k is a reasonable
//     range as of 2026.
//   - salt should be unique per password; 16 random bytes is the typical
//     minimum.
//   - The returned slice is a fresh allocation; the caller may zero it via
//     memsecure.ZeroBytes when finished.
func PBKDF2(password, salt []byte, iter, keyLen int, h func() hash.Hash) ([]byte, error) {
	if iter <= 0 {
		return nil, ErrInvalidIteration
	}
	if keyLen <= 0 {
		return nil, ErrInvalidKeyLen
	}
	if h == nil {
		return nil, errors.New("kdf: hash factory must not be nil")
	}

	prf := hmac.New(h, password)
	hLen := prf.Size()

	numBlocks := (keyLen + hLen - 1) / hLen
	dk := make([]byte, 0, numBlocks*hLen)

	var block [4]byte
	u := make([]byte, hLen)
	t := make([]byte, hLen)

	for i := 1; i <= numBlocks; i++ {
		binary.BigEndian.PutUint32(block[:], uint32(i))

		// U_1 = PRF(password, salt || INT_32_BE(i))
		prf.Reset()
		prf.Write(salt)
		prf.Write(block[:])
		u = prf.Sum(u[:0])
		copy(t, u)

		// U_j = PRF(password, U_{j-1}); T = U_1 ^ U_2 ^ ... ^ U_c
		for j := 2; j <= iter; j++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for k := 0; k < hLen; k++ {
				t[k] ^= u[k]
			}
		}

		dk = append(dk, t...)
	}

	return dk[:keyLen], nil
}
