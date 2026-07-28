package sm4

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	gmsmSM4 "github.com/emmansun/gmsm/sm4"
)

const (
	// BlockSize is the SM4 block size in bytes.
	BlockSize = gmsmSM4.BlockSize

	// KeySize is the SM4 key size in bytes.
	KeySize = 16
)

// NewCipher creates and returns a new cipher.Block implementing SM4.
// The key argument must be 16 bytes.
func NewCipher(key []byte) (cipher.Block, error) {
	return gmsmSM4.NewCipher(key)
}

// GenerateKey generates a random 128-bit SM4 key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, errors.New("sm4: failed to generate key")
	}
	return key, nil
}
