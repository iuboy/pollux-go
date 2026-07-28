package sm4

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/iuboy/pollux-go/internal/memsecure"
)

// GCMNonceSize is the standard nonce size for SM4-GCM (12 bytes, per RFC 8998
// and NIST SP 800-38D). SM4-GCM does NOT support non-standard nonce sizes.
const GCMNonceSize = 12

// Sealed holds the result of SealRandomNonce: a randomly generated nonce and
// the ciphertext authenticated against it. Callers MUST store both together —
// decryption requires the same nonce.
type Sealed struct {
	Nonce      []byte
	Ciphertext []byte
}

// GenerateNonce generates a cryptographically random 12-byte nonce suitable
// for SM4-GCM.
//
// Each encryption under the same key MUST use a unique nonce. Nonce reuse with
// GCM is catastrophic: it allows key recovery and message forgery. Prefer
// SealRandomNonce, which binds nonce generation to the encrypt path.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, GCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.New("sm4: failed to generate nonce")
	}
	return nonce, nil
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
	aead, err := NewGCM(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, s.Nonce, s.Ciphertext, aad)
}

// ZeroKey securely zeroes an SM4 key slice. It delegates to
// memsecure.ZeroBytes, which uses crypto/subtle XOR + unsafe write +
// runtime.KeepAlive to resist dead-store elimination. Call via defer after
// the key is no longer needed.
func ZeroKey(key []byte) { memsecure.ZeroBytes(key) }

// ZeroNonce securely zeroes an SM4-GCM nonce slice. See ZeroKey for the
// implementation details.
func ZeroNonce(nonce []byte) { memsecure.ZeroBytes(nonce) }
