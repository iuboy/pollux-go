package sm3

import (
	"hash"

	gmsmSM3 "github.com/emmansun/gmsm/sm3"
)

const (
	// Size is the size of an SM3 checksum in bytes. References the gmsm
	// definition so the two cannot drift.
	Size = gmsmSM3.Size

	// BlockSize is the block size of SM3 in bytes. References the gmsm
	// definition for the same reason as Size.
	BlockSize = gmsmSM3.BlockSize
)

// New returns a new hash.Hash computing the SM3 checksum.
func New() hash.Hash {
	return gmsmSM3.New()
}

// Sum returns the SM3 checksum of the data.
func Sum(data []byte) [Size]byte {
	return gmsmSM3.Sum(data)
}
