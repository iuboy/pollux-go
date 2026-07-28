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
