package kdf

import (
	stdpbkdf2 "crypto/pbkdf2"
	"errors"
	"fmt"
	"hash"
)

// ErrInvalidIteration is returned when the iteration count is not positive.
var ErrInvalidIteration = errors.New("kdf: iteration count must be positive")

// ErrInvalidKeyLen is returned when the requested derived-key length is not
// positive. RFC 2898 permits any positive dkLen; the upper bound is enforced
// by the caller's hash output size times 2^32 - 1, which is far beyond any
// practical request.
var ErrInvalidKeyLen = errors.New("kdf: key length must be positive")

// ErrInvalidSalt is returned when the salt is empty. An empty salt makes the
// derivation deterministic across all users of the same password, defeating
// rainbow-table resistance outright; RFC 2898 test vectors use non-empty
// salts (4 bytes) and remain valid. Password-hashing callers that want a
// stronger floor (e.g. the pwHash package's 8-byte minimum) enforce it at
// their own trust boundary.
var ErrInvalidSalt = errors.New("kdf: salt must not be empty")

// ErrSaltTooLong is returned when the salt exceeds [MaxSaltLen]. It bounds the
// memory amplification of attacker-controlled salts (e.g. salt fields parsed
// from untrusted PHC strings or ASN.1) — the salt is hashed internally by
// HMAC, but it is copied into the hash's inner/outer pads and every
// intermediate buffer, so an unbounded salt turns one derivation into a
// memory-exhaustion primitive.
var ErrSaltTooLong = errors.New("kdf: salt length exceeds limit")

// MaxSaltLen is the upper bound on the salt length accepted by [PBKDF2]:
// 64 KiB. It is the single shared bound enforced by every PBKDF2 call site in
// this module (the pwHash decoder clamps decoded PHC salts to it and the
// smx509 PBES2 decryptor clamps attacker-controlled ASN.1 salts to it), so
// the three layers agree on one number. It is far above any legitimate salt
// (16–64 bytes is typical) and far below any allocation worth attacking.
const MaxSaltLen = 1 << 16

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
// The derivation is delegated to the standard library crypto/pbkdf2 (added in
// Go 1.24; golang.org/x/crypto/pbkdf2 is its frozen ancestor); this wrapper
// preserves the package's input-validation boundary and (result, error)
// signature so callers — notably the pwhash package's pbkdf2-sm3 hasher — are
// unaffected by the underlying switch.
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
//   - SECURITY: password crosses the stdlib boundary via string(password),
//     which copies it onto the heap in a form Go provides no API to erase —
//     the copy can outlive this call in GC-unreachable-but-unwiped memory.
//     High-sensitivity paths (raw key-derivation from passphrase-controlled
//     secrets where the caller already holds the password in an erasable
//     []byte) must weigh that residual exposure themselves; this wrapper
//     deliberately does not add a zero-copy variant to avoid forking the
//     API surface (第四轮审计 P3 记录项,文档化处置).
//   - The returned slice is a fresh allocation; the caller may zero it via
//     memsecure.ZeroBytes when finished.
//
// iter and keyLen are bounded above to reject attacker-controlled pathological
// values (e.g. those parsed from untrusted PHC strings) that would otherwise
// cause CPU exhaustion. The salt is bounded to [MaxSaltLen] (64 KiB) for the
// same reason — memory amplification instead of CPU. All bounds are well
// above any legitimate use.
//
// FIPS note: under GODEBUG=fips140=only the stdlib rejects non-approved
// hashes (SM3 among them); the error is propagated rather than silently
// deriving GM keys inside a process that explicitly opted into FIPS-only
// crypto.
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
	if len(salt) == 0 {
		return nil, ErrInvalidSalt
	}
	// 第四轮审计 P3:盐无上限时,来自不可信输入(PHC 字符串、ASN.1)的畸形盐
	// 会放大派生的内存足迹。64 KiB 远高于任何合法盐(典型 16~64 字节)。
	if len(salt) > MaxSaltLen {
		return nil, fmt.Errorf("kdf: salt length %d exceeds limit %d: %w", len(salt), MaxSaltLen, ErrSaltTooLong)
	}

	// stdlib crypto/pbkdf2.Key signature: Key(h, password string, salt, iter,
	// keyLength) ([]byte, error). The password crosses the boundary as string
	// (the stdlib convention to discourage retaining attacker data); the
	// conversion does leave an un-erasable heap copy — see the Security notes
	// in the doc comment above.
	dk, err := stdpbkdf2.Key(h, string(password), salt, iter, keyLen)
	if err != nil {
		return nil, fmt.Errorf("kdf: pbkdf2: %w", err)
	}
	return dk, nil
}
