package tls13gm

import (
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/iuboy/pollux-go/sm4"
)

var errCCMNotImplemented = errors.New("tls13gm: SM4-CCM is not yet implemented; requires a CCM cipher mode library")

// NewCCMAEAD creates an SM4-CCM AEAD cipher for TLS 1.3 packet protection.
//
// SM4-CCM is defined in RFC 8998 (cipher suite 0x00C7). Unlike SM4-GCM, CCM
// is not provided by Go's crypto/cipher standard library, so a third-party CCM
// implementation is required.
//
// TODO: Implement once a suitable CCM library is integrated. The interface
// mirrors NewAEAD (SM4-GCM) so callers can switch transparently.
func NewCCMAEAD(key, nonce []byte) (*CCMAEAD, error) {
	if len(nonce) != 12 {
		return nil, fmt.Errorf("tls13gm: CCM nonce must be 12 bytes for TLS 1.3, got %d", len(nonce))
	}
	return nil, errCCMNotImplemented
}

// CCMAEAD provides SM4-CCM encryption/decryption for TLS 1.3 records.
// This is a placeholder until a CCM implementation is available.
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

// computeCCMNonce computes the nonce by XORing the sequence number into the
// fixed nonce, identical to the GCM nonce construction in TLS 1.3.
func computeCCMNonce(fixedNonce []byte, seqNum uint64) []byte {
	nonce := make([]byte, len(fixedNonce))
	copy(nonce, fixedNonce)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(seqNum >> (i * 8))
	}
	return nonce
}

// newCCMAEADInternal creates a CCMAEAD from a constructed cipher.AEAD.
// This is unexported so it can be used in tests once a CCM implementation
// is available.
//
//nolint:unused
func newCCMAEADInternal(aead cipher.AEAD, fixedNonce []byte) (*CCMAEAD, error) {
	if aead == nil {
		return nil, errors.New("tls13gm: aead is nil")
	}
	if len(fixedNonce) != 12 {
		return nil, fmt.Errorf("tls13gm: CCM nonce must be 12 bytes, got %d", len(fixedNonce))
	}
	return &CCMAEAD{aead: aead, fixedNonce: fixedNonce}, nil
}

// ensure sm4.NewCipher is referenced (used when CCM is implemented).
var _ = sm4.NewCipher

// Suppress unused warning for internal helper (used when CCM is integrated).
var _ = newCCMAEADInternal
