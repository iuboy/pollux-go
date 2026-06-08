// Package sm4gcm provides SM4-GCM authenticated encryption.
//
// Deprecated: this package duplicates functionality available directly from
// sm4.NewCipher + cipher.NewGCM. Use those instead. This package will be
// removed in a future release.
package sm4gcm

import (
	"crypto/cipher"
	"errors"
	"io"

	"github.com/ycq/pollux/internal/memsecure"
	"github.com/ycq/pollux/sm4"
)

const (
	KeySize   = 16
	NonceSize = 12
)

var (
	errInvalidKeySize   = errors.New("sm4gcm: key must be 16 bytes")
	errInvalidNonceSize = errors.New("sm4gcm: nonce must be 12 bytes")
)

// Sealed holds the result of SealRandomNonce.
type Sealed struct {
	Nonce      []byte
	Ciphertext []byte
}

// GenerateKey generates a random 16-byte SM4 key.
func GenerateKey(r io.Reader) ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, errors.New("sm4gcm: failed to generate key")
	}
	return key, nil
}

// GenerateNonce generates a random 12-byte nonce.
func GenerateNonce(r io.Reader) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, errors.New("sm4gcm: failed to generate nonce")
	}
	return nonce, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errInvalidKeySize
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plaintext with the given key, nonce, and AAD.
// WARNING: never reuse a nonce with the same key. GCM nonce reuse
// completely breaks authentication. Prefer SealRandomNonce for safety.
func Seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, errInvalidNonceSize
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts ciphertext with the given key, nonce, and AAD.
func Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, errInvalidNonceSize
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

// SealRandomNonce encrypts plaintext with a random nonce and returns both.
func SealRandomNonce(r io.Reader, key, plaintext, aad []byte) (Sealed, error) {
	nonce, err := GenerateNonce(r)
	if err != nil {
		return Sealed{}, err
	}
	ct, err := Seal(key, nonce, plaintext, aad)
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{Nonce: nonce, Ciphertext: ct}, nil
}

// ZeroKey securely zeroes an SM4 key.
func ZeroKey(key []byte) {
	memsecure.ZeroBytes(key)
}

// ZeroNonce securely zeroes an SM4-GCM nonce.
func ZeroNonce(nonce []byte) {
	memsecure.ZeroBytes(nonce)
}
