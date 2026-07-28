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
