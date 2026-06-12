package tls13gm

import (
	"crypto/cipher"
	"errors"

	"github.com/iuboy/pollux-go/sm4"
)

var errInvalidNonceLen = errors.New("tls13gm: nonce must be 12 bytes for TLS 1.3 SM4-GCM")

// NewAEAD creates an SM4-GCM AEAD cipher for TLS 1.3 packet protection.
// The SM4-GCM cipher.AEAD is initialized once at construction time for efficiency.
// Returns an error if nonce is not exactly 12 bytes (TLS 1.3 SM4-GCM nonce length).
func NewAEAD(key, nonce []byte) (*AEAD, error) {
	if len(nonce) != 12 {
		return nil, errInvalidNonceLen
	}
	aead, err := sm4.NewGCM(key)
	if err != nil {
		return nil, err
	}
	return &AEAD{aead: aead, fixedNonce: nonce}, nil
}

// AEAD provides SM4-GCM encryption/decryption for TLS 1.3 records.
type AEAD struct {
	aead       cipher.AEAD
	fixedNonce []byte
}

// Seal encrypts with a sequence-number-based nonce.
func (a *AEAD) Seal(seqNum uint64, plaintext, aad []byte) ([]byte, error) {
	nonce := a.computeNonce(seqNum)
	return a.aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts with a sequence-number-based nonce.
func (a *AEAD) Open(seqNum uint64, ciphertext, aad []byte) ([]byte, error) {
	nonce := a.computeNonce(seqNum)
	return a.aead.Open(nil, nonce, ciphertext, aad)
}

func (a *AEAD) computeNonce(seqNum uint64) []byte {
	nonce := make([]byte, len(a.fixedNonce))
	copy(nonce, a.fixedNonce)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(seqNum >> (i * 8))
	}
	return nonce
}
