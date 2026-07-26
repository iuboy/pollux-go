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
		return nil, fmt.Errorf("aes: failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// NewGCM creates an AES-256-GCM authenticated encryptor.
// The returned cipher.AEAD can be used directly for Seal/Open.
//
// Key handling: the key bytes are passed to crypto/aes.NewCipher, which
// copies them into the cipher's internal key schedule. The caller's key
// slice is NOT retained — callers should zero it via defer ZeroKey(key)
// after the AEAD is constructed. The one-shot convenience functions
// (SealRandomNonce, SealCombined, OpenWithNonce, OpenCombined) consume the
// key themselves and never return it to a useful state; callers that reuse
// a single AEAD across many messages must use NewGCM directly and manage
// zeroing themselves (defer ZeroKey after construction).
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
// Key hygiene: the caller's key slice is securely zeroed (via ZeroKey) before
// the function returns. This is the documented contract of every one-shot
// convenience function in this package: the key is consumed. Callers that
// need to reuse the key across multiple operations MUST clone it before
// passing it in, or use NewGCM directly and manage zeroing themselves.
//
// For performance-sensitive code that encrypts many messages under one key,
// construct a single cipher.AEAD via NewGCM and reuse it, generating a new
// nonce per message via GenerateNonce. In that case defer ZeroKey(key) once
// after construction.
func SealRandomNonce(key, plaintext, aad []byte) (Sealed, error) {
	defer ZeroKey(key) // consume caller's key (already copied into key schedule)
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
//
// Key hygiene: see SealRandomNonce — the caller's key is consumed (zeroed)
// before return.
func OpenWithNonce(key []byte, s Sealed, aad []byte) ([]byte, error) {
	defer ZeroKey(key) // consume caller's key
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
//
// Key hygiene: see SealRandomNonce — the caller's key is consumed (zeroed)
// before return.
func SealCombined(key, plaintext, aad []byte) ([]byte, error) {
	defer ZeroKey(key) // consume caller's key
	aead, err := NewGCM(key)
	if err != nil {
		return nil, err
	}
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}
	// Seal appends ciphertext+tag to the first argument (dst); passing nonce
	// as both dst and nonce yields the desired nonce || ct layout. This uses
	// the Go stdlib's documented Seal behavior: "dst and plaintext must not
	// overlap exactly, but may overlap partially" — nonce (12 bytes) is
	// shorter than the final output (12 + len(plaintext) + 16 tag), so Seal
	// will allocate a new backing array rather than mutating nonce in place.
	// The returned slice is thus independent of nonce. This matches the
	// de-facto crypto/cipher.AEAD.Seal-with-prepend idiom used across the Go
	// ecosystem (e.g. Go's own crypto/tls record protection).
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

// OpenCombined decrypts a blob produced by SealCombined (nonce || ciphertext+tag).
// It is the inverse of SealCombined.
//
// Short inputs are rejected explicitly rather than degrading to an all-zero
// nonce, which would mask caller misuse (truncated ciphertext, forgotten
// nonce) as a generic decryption failure.
//
// Key hygiene: see SealRandomNonce — the caller's key is consumed (zeroed)
// before return.
func OpenCombined(key, ciphertext, aad []byte) ([]byte, error) {
	defer ZeroKey(key) // consume caller's key
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
