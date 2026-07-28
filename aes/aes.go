package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const (
	// BlockSize is the AES block size in bytes (FIPS 197).
	BlockSize = aes.BlockSize

	// KeySize is the only key size this package supports: 32 bytes (AES-256).
	// AES-128 and AES-192 are intentionally omitted (see package doc).
	KeySize = 32
)

// ErrInvalidKeySize is returned when a key whose length is not KeySize is
// passed to NewCipher or any convenience function.
var ErrInvalidKeySize = errors.New("aes: key must be 32 bytes (AES-256)")

// NewCipher creates and returns a new cipher.Block implementing AES-256.
// The key argument must be exactly 32 bytes.
//
// This is a thin wrapper around crypto/aes.NewCipher that enforces the
// AES-256-only policy of this package at the boundary.
func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}
	return aes.NewCipher(key)
}

// GenerateKey generates a random 256-bit AES key using crypto/rand.
// The caller MUST securely zero the returned slice when done, preferably via
// defer ZeroKey(key).
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, errors.New("aes: failed to generate key")
	}
	return key, nil
}
