package tls13gm

import (
	"github.com/ycq/pollux/sm4gcm"
)

// NewAEAD creates an SM4-GCM AEAD cipher for TLS 1.3 packet protection.
// This is a thin wrapper around sm4gcm.Seal/Open for TLS 1.3 record protection.
// Panics if nonce is not exactly 12 bytes (TLS 1.3 SM4-GCM nonce length).
func NewAEAD(key, nonce []byte) *AEAD {
	if len(nonce) != 12 {
		panic("tls13gm: nonce must be 12 bytes for TLS 1.3 SM4-GCM")
	}
	return &AEAD{key: key, fixedNonce: nonce}
}

// AEAD provides SM4-GCM encryption/decryption for TLS 1.3 records.
type AEAD struct {
	key        []byte
	fixedNonce []byte
}

// Seal encrypts with a sequence-number-based nonce.
func (a *AEAD) Seal(seqNum uint64, plaintext, aad []byte) ([]byte, error) {
	nonce := a.computeNonce(seqNum)
	return sm4gcm.Seal(a.key, nonce, plaintext, aad)
}

// Open decrypts with a sequence-number-based nonce.
func (a *AEAD) Open(seqNum uint64, ciphertext, aad []byte) ([]byte, error) {
	nonce := a.computeNonce(seqNum)
	return sm4gcm.Open(a.key, nonce, ciphertext, aad)
}

func (a *AEAD) computeNonce(seqNum uint64) []byte {
	nonce := make([]byte, len(a.fixedNonce))
	copy(nonce, a.fixedNonce)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(seqNum >> (i * 8))
	}
	return nonce
}
