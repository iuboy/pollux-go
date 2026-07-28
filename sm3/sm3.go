// Package sm3 implements the SM3 cryptographic hash function (GM/T 0004-2012).
//
// SM3 is a cryptographic hash algorithm published by the Chinese National
// Cryptography Administration. It produces a 256-bit (32-byte) digest.
//
// The API follows crypto/sha256 conventions:
//
//	h := sm3.New()
//	h.Write(data)
//	digest := h.Sum(nil)
//
//	// Or use the one-shot function:
//	digest := sm3.Sum(data)
//
// Status: wrapper around gmsm/sm3
package sm3

import (
	"hash"

	"github.com/emmansun/gmsm/sm3"
)

const (
	// Size is the size of an SM3 checksum in bytes.
	Size = 32

	// BlockSize is the block size of SM3 in bytes.
	BlockSize = 64
)

// New returns a new hash.Hash computing the SM3 checksum.
func New() hash.Hash {
	return sm3.New()
}

// Sum returns the SM3 checksum of the data.
func Sum(data []byte) [Size]byte {
	return sm3.Sum(data)
}
