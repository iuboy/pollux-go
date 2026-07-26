package gmstd

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// SM4KeySize is the SM4 key size in bytes (128 bits, per GB/T 32907).
const SM4KeySize = 16

// maxNonceSize bounds GenerateNonce's allocation to protect against
// accidental or malicious huge size arguments (OOM/DoS).
const maxNonceSize = 1 << 20 // 1 MiB

// GenerateSM4Key generates a 16-byte random SM4 key.
func GenerateSM4Key() ([]byte, error) {
	key := make([]byte, SM4KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("gmstd: key generation failed: %w", err)
	}
	return key, nil
}

// GenerateNonce generates a random nonce of the specified size.
// Returns an error if size is non-positive or exceeds maxNonceSize.
func GenerateNonce(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("gmstd: nonce size must be positive")
	}
	if size > maxNonceSize {
		return nil, fmt.Errorf("gmstd: nonce size %d exceeds max %d", size, maxNonceSize)
	}
	nonce := make([]byte, size)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("gmstd: random generation failed: %w", err)
	}
	return nonce, nil
}
