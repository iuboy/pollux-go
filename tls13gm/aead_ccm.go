package tls13gm

import (
	"crypto/cipher"
	"fmt"

	smcipher "github.com/emmansun/gmsm/cipher"
	"github.com/iuboy/pollux-go/sm4"
)

// NewCCMAEAD creates an SM4-CCM AEAD cipher for TLS 1.3 record protection.
//
// SM4-CCM is defined in RFC 8998 (cipher suite 0x00C7, TLS_SM4_CCM_SM3). CCM is
// not provided by Go's crypto/cipher standard library, so the gmsm CCM mode
// (github.com/emmansun/gmsm/cipher) is used. The nonce construction mirrors
// SM4-GCM: a fixed 12-byte IV XORed with the 8-byte big-endian sequence number.
// The authentication tag is 16 bytes, as required for TLS 1.3.
//
// Note: RFC 8998 defines no QUIC cipher suite for SM4-CCM (only TLS_SM4_GCM_SM3
// 0x00C6 is used over QUIC), so this AEAD serves the TLS record layer, not QUIC
// packet protection. The interface mirrors NewAEAD (SM4-GCM) so callers can
// switch between the two GM AEAD modes transparently.
func NewCCMAEAD(key, nonce []byte) (*CCMAEAD, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("tls13gm: CCM key must be 16 bytes (SM4-128), got %d", len(key))
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("tls13gm: CCM nonce must be 12 bytes for TLS 1.3, got %d", len(nonce))
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("tls13gm: SM4 cipher: %w", err)
	}
	aead, err := smcipher.NewCCMWithNonceAndTagSize(block, len(nonce), 16)
	if err != nil {
		return nil, fmt.Errorf("tls13gm: SM4-CCM: %w", err)
	}
	return &CCMAEAD{aead: aead, fixedNonce: append([]byte(nil), nonce...)}, nil
}

// CCMAEAD provides SM4-CCM encryption/decryption for TLS 1.3 records.
type CCMAEAD struct {
	aead       cipher.AEAD
	fixedNonce []byte
}

// Seal encrypts with a sequence-number-based nonce.
func (a *CCMAEAD) Seal(seqNum uint64, plaintext, aad []byte) ([]byte, error) {
	nonce := computeCCMNonce(a.fixedNonce, seqNum)
	return a.aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts with a sequence-number-based nonce.
func (a *CCMAEAD) Open(seqNum uint64, ciphertext, aad []byte) ([]byte, error) {
	nonce := computeCCMNonce(a.fixedNonce, seqNum)
	return a.aead.Open(nil, nonce, ciphertext, aad)
}

// Overhead returns the AEAD authentication-tag size in bytes (16 for SM4-CCM),
// i.e. the number of bytes Seal appends to the plaintext.
func (a *CCMAEAD) Overhead() int { return a.aead.Overhead() }

// computeCCMNonce computes the nonce by XORing the sequence number into the
// fixed nonce, identical to the GCM nonce construction in TLS 1.3.
func computeCCMNonce(fixedNonce []byte, seqNum uint64) []byte {
	nonce := make([]byte, len(fixedNonce))
	copy(nonce, fixedNonce)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(seqNum >> (i * 8))
	}
	return nonce
}
