// Package sm4 implements the SM4 block cipher (GM/T 0002-2012).
//
// SM4 is a block cipher with a fixed block size of 128 bits and a key size
// of 128 bits, standardized by the Chinese National Cryptography Administration.
//
// The API follows crypto/aes conventions:
//
//	block, err := sm4.NewCipher(key)
//
//	// Use with standard library modes:
//	aead, err := cipher.NewGCM(block)
//	cbc := cipher.NewCBCEncrypter(block, iv)
//	ctr := cipher.NewCTR(block, iv)
//
// # Security: nonce and IV reuse
//
// Reusing a nonce (GCM) or IV (CBC, CTR, CFB) with the same key is catastrophic:
//
//   - GCM: nonce reuse allows key recovery and message forgery.
//   - CTR: reuse produces a two-time pad, leaking plaintext via XOR.
//   - CBC: reuse enables block-wise correlation attacks.
//
// For GCM encryption, use GenerateNonce to create a cryptographically random
// 12-byte nonce for each encryption, or use the sm4gcm package which provides
// a higher-level API with SealRandomNonce.
//
// ECB mode (NewECBEncrypter/NewECBDecrypter) is provided for compatibility only
// and should not be used in new protocols — it does not provide semantic security.
//
// Status: wrapper around gmsm/sm4
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
