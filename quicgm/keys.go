package quicgm

import (
	"errors"
	"fmt"
	"io"
)

const (
	hmacKeySize  = 32
	sm4KeySize   = 16
	keyIDLen     = 16
	sessionIDLen = 16
)

var (
	errEmptyKeyID            = errors.New("quicgm: KeyID must not be empty")
	errEmptySessionID        = errors.New("quicgm: SessionID must not be empty")
	errMACVerificationFailed = errors.New("quicgm: MAC verification failed")
	errUnsupportedVersion    = errors.New("quicgm: unsupported envelope version")
	errInvalidNonceLength    = errors.New("quicgm: nonce must be 12 bytes")
	errNonceReuse            = errors.New("quicgm: nonce already used for this KeyID/SessionID")
)

// SessionKeys holds a pair of keys for HMAC-SM3 and SM4-GCM.
type SessionKeys struct {
	KeyID     string
	HMACKey   []byte
	SM4Key    []byte
	SessionID string
}

// GenerateSessionKeys generates a new set of session keys.
func GenerateSessionKeys(r io.Reader) (SessionKeys, error) {
	hmacKey := make([]byte, hmacKeySize)
	if _, err := io.ReadFull(r, hmacKey); err != nil {
		return SessionKeys{}, errors.New("quicgm: failed to generate HMAC key")
	}
	sm4Key := make([]byte, sm4KeySize)
	if _, err := io.ReadFull(r, sm4Key); err != nil {
		return SessionKeys{}, errors.New("quicgm: failed to generate SM4 key")
	}
	keyID := make([]byte, keyIDLen)
	if _, err := io.ReadFull(r, keyID); err != nil {
		return SessionKeys{}, errors.New("quicgm: failed to generate KeyID")
	}
	sessionID := make([]byte, sessionIDLen)
	if _, err := io.ReadFull(r, sessionID); err != nil {
		return SessionKeys{}, errors.New("quicgm: failed to generate SessionID")
	}
	return SessionKeys{
		KeyID:     fmt.Sprintf("%x", keyID),
		HMACKey:   hmacKey,
		SM4Key:    sm4Key,
		SessionID: fmt.Sprintf("%x", sessionID),
	}, nil
}
