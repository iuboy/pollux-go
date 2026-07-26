// Package sha provides SHA-256/HKDF/HMAC wrappers that serve as the
// international (non-GM) counterpart to the sm3 package. The API surface
// mirrors sm3 so callers can treat SM3 and SHA-256 interchangeably by
// configuration.
//
// The wrappers are intentionally thin — they exist so the pollux-go
// codebase has a uniform "hash package" shape across both regimes
// (sm3 for GM, sha for international). The exported constants (Size,
// BlockSize) reference crypto/sha256's definitions directly so they
// cannot drift. Callers already importing crypto/sha256 directly do
// NOT need this package; it is for code that abstracts over the
// sm3/sha pair.
package sha

import (
	"crypto/sha256"
	"hash"
)

const (
	// Size is the size of a SHA-256 checksum in bytes.
	Size = sha256.Size

	// BlockSize is the block size of SHA-256 in bytes.
	BlockSize = sha256.BlockSize
)

// New returns a new hash.Hash computing the SHA-256 checksum.
func New() hash.Hash {
	return sha256.New()
}

// Sum returns the SHA-256 checksum of the data.
func Sum(data []byte) [Size]byte {
	return sha256.Sum256(data)
}
