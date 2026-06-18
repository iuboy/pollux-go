package gmstd

import (
	"crypto/rand"
	"errors"
)

// SM4KeySize is the SM4 key size in bytes (128 bits, per GB/T 32907).
const SM4KeySize = 16

// GenerateSM4Key generates a 16-byte random SM4 key.
func GenerateSM4Key() ([]byte, error) {
	key := make([]byte, SM4KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, errors.New("gmstd: key generation failed")
	}
	return key, nil
}

// GenerateNonce generates a random nonce of the specified size.
func GenerateNonce(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("gmstd: invalid size")
	}
	nonce := make([]byte, size)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("gmstd: random generation failed")
	}
	return nonce, nil
}
