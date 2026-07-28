package aes

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/iuboy/pollux-go/internal/memsecure"
)

// GCMNonceSize is the standard nonce size for AES-GCM (12 bytes, per NIST SP
// 800-38D). AES-GCM, unlike SM4-GCM, technically supports non-standard nonce
// sizes via cipher.NewGCMWithNonceSize, but this package intentionally does
// not expose that — the 12-byte nonce is the universally interoperable choice.
const GCMNonceSize = 12

// Sealed holds the result of SealRandomNonce: a randomly generated nonce and
// the ciphertext authenticated against it. Callers MUST store both together —
// decryption requires the same nonce.
//
// For at-rest formats that prefer a single concatenated blob (nonce || ct),
// use SealCombined instead.
type Sealed struct {
	Nonce      []byte
	Ciphertext []byte
}

// GenerateNonce generates a cryptographically random 12-byte nonce suitable
// for AES-GCM.
//
// Each encryption under the same key MUST use a unique nonce. Nonce reuse with
// GCM is catastrophic: it allows key recovery and message forgery. Prefer
// SealRandomNonce, which binds nonce generation to the encrypt path.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, GCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.New("aes: failed to generate nonce")
	}
	return nonce, nil
}

// NewGCM creates an AES-256-GCM authenticated encryptor.
// The returned cipher.AEAD can be used directly for Seal/Open.
func NewGCM(key []byte) (cipher.AEAD, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// SealRandomNonce encrypts plaintext with a freshly generated random nonce
// and returns both as a Sealed value. This is the recommended one-shot API:
// it eliminates the risk of nonce reuse by binding nonce generation to the
// encrypt call.
//
// For performance-sensitive code that encrypts many messages under one key,
// construct a single cipher.AEAD via NewGCM and reuse it, generating a new
// nonce per message via GenerateNonce.
func SealRandomNonce(key, plaintext, aad []byte) (Sealed, error) {
	aead, err := NewGCM(key)
	if err != nil {
		return Sealed{}, err
	}
	nonce, err := GenerateNonce()
	if err != nil {
		return Sealed{}, err
	}
	ct := aead.Seal(nil, nonce, plaintext, aad)
	return Sealed{Nonce: nonce, Ciphertext: ct}, nil
}

// OpenWithNonce decrypts a Sealed value produced by SealRandomNonce. It is a
// thin convenience over aead.Open that pulls the nonce out of the Sealed value.
func OpenWithNonce(key []byte, s Sealed, aad []byte) ([]byte, error) {
	if len(s.Nonce) != GCMNonceSize {
		return nil, fmt.Errorf("aes: invalid nonce length %d, want %d", len(s.Nonce), GCMNonceSize)
	}
	aead, err := NewGCM(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, s.Nonce, s.Ciphertext, aad)
}

// SealCombined encrypts plaintext and returns nonce || ciphertext+tag as a
// single byte slice. This format matches the de-facto AEAD wire format used
// by many at-rest encryption layers (including Go's
// crypto/cipher.AEAD.Seal-with-prepend idiom) and is byte-compatible with
// existing AES-256-GCM ciphertexts produced by those layers.
//
// Use OpenCombined to decrypt. The combined format saves the caller from
// managing two slices at the cost of one extra allocation on decrypt.
func SealCombined(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := NewGCM(key)
	if err != nil {
		return nil, err
	}
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}
	// Seal appends ciphertext+tag to the first argument; passing nonce as the
	// dst yields the desired nonce || ct layout in a single allocation.
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

// OpenCombined decrypts a blob produced by SealCombined (nonce || ciphertext+tag).
// It is the inverse of SealCombined.
//
// Short inputs are rejected explicitly rather than degrading to an all-zero
// nonce, which would mask caller misuse (truncated ciphertext, forgotten
// nonce) as a generic decryption failure.
func OpenCombined(key, ciphertext, aad []byte) ([]byte, error) {
	aead, err := NewGCM(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, errNonceMissing
	}
	nonce := ciphertext[:aead.NonceSize()]
	body := ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, body, aad)
}

// ZeroKey securely zeroes an AES key slice. It delegates to
// memsecure.ZeroBytes, which uses crypto/subtle XOR + unsafe write +
// runtime.KeepAlive to resist dead-store elimination. Call via defer after
// the key is no longer needed.
func ZeroKey(key []byte) { memsecure.ZeroBytes(key) }

// ZeroNonce securely zeroes an AES-GCM nonce slice. See ZeroKey for the
// implementation details.
func ZeroNonce(nonce []byte) { memsecure.ZeroBytes(nonce) }

var errNonceMissing = errors.New("aes: nonce required (none provided and ciphertext too short to contain a prepended one)")
