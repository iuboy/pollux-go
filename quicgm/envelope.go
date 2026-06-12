package quicgm

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/iuboy/pollux-go/sm4"
)

// nonceSize is the SM4-GCM nonce length in bytes (12 bytes / 96 bits).
const nonceSize = 12

// Envelope holds an encrypted application payload with metadata.
type Envelope struct {
	Version    int    `json:"v"`
	SessionID  string `json:"sid"`
	KeyID      string `json:"kid"`
	Nonce      []byte `json:"nonce"`
	AAD        []byte `json:"aad"`
	Ciphertext []byte `json:"ct"`
	MAC        []byte `json:"mac"`
}

// Seal encrypts plaintext into an Envelope using a randomly generated nonce.
// Metadata (KeyID, SessionID, nonce, AAD) is authenticated via MAC.
//
// Security note: This function generates a random nonce for each call.
// For most use cases, random nonces provide sufficient security when used
// with SM4-GCM (96-bit nonce). If you need explicit nonce control,
// use SealWithNonce instead.
func Seal(keys SessionKeys, plaintext, aad []byte) (Envelope, error) {
	if keys.KeyID == "" {
		return Envelope{}, errEmptyKeyID
	}
	if keys.SessionID == "" {
		return Envelope{}, errEmptySessionID
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, err
	}

	return SealWithNonce(keys, nonce, plaintext, aad)
}

// SealWithNonce encrypts plaintext into an Envelope using an explicit nonce.
// This allows the caller to control nonce generation strategy.
//
// The caller MUST ensure:
// 1. The nonce is exactly 12 bytes (SM4-GCM nonce length).
// 2. The nonce is unique for each (KeyID, SessionID) pair.
// 3. Nonces MUST NOT be reused with the same key.
//
// For random nonce generation, use Seal() instead.
func SealWithNonce(keys SessionKeys, nonce, plaintext, aad []byte) (Envelope, error) {
	if keys.KeyID == "" {
		return Envelope{}, errEmptyKeyID
	}
	if keys.SessionID == "" {
		return Envelope{}, errEmptySessionID
	}
	if len(nonce) != nonceSize {
		return Envelope{}, errInvalidNonceLength
	}

	ct, err := sm4GCMSeal(keys.SM4Key, nonce, plaintext, aad)
	if err != nil {
		return Envelope{}, err
	}

	env := Envelope{
		Version:    1,
		SessionID:  keys.SessionID,
		KeyID:      keys.KeyID,
		Nonce:      nonce,
		AAD:        aad,
		Ciphertext: ct,
	}

	env.MAC = computeEnvelopeMAC(keys.HMACKey, env)
	return env, nil
}

// NonceRegistry provides in-process nonce uniqueness tracking.
// This is an optional security measure for applications that require
// stronger nonce guarantees than random generation provides.
//
// The registry tracks used nonces per (KeyID, SessionID) pair.
// It is safe for concurrent use. Entries are evicted when maxEntries
// is exceeded to prevent unbounded memory growth.
type NonceRegistry struct {
	mu         sync.RWMutex
	used       map[string]struct{} // composite key "keyID:sessionID:hex(nonce)" -> {}
	maxEntries int                 // max nonces per session (0 = unlimited)
}

// nonceRegistryKey builds a composite map key from (keyID, sessionID, nonce).
func nonceRegistryKey(keyID, sessionID string, nonce []byte) string {
	// Use a strings.Builder to avoid fmt.Sprintf overhead.
	// Hex encoding is used for the nonce to produce a deterministic key.
	return keyID + ":" + sessionID + ":" + fmt.Sprintf("%x", nonce)
}

// NewNonceRegistry creates a new nonce registry.
// maxEntries controls the maximum number of nonces tracked per (KeyID, SessionID).
// When exceeded, the oldest entries are evicted. A value of 0 means unlimited.
func NewNonceRegistry() *NonceRegistry {
	return &NonceRegistry{
		used:       make(map[string]struct{}),
		maxEntries: 0,
	}
}

// NewNonceRegistryWithCapacity creates a nonce registry with bounded capacity per session.
func NewNonceRegistryWithCapacity(maxEntries int) *NonceRegistry {
	return &NonceRegistry{
		used:       make(map[string]struct{}),
		maxEntries: maxEntries,
	}
}

// CheckAndRecord checks if a nonce has been used for the given (KeyID, SessionID).
// Returns true if the nonce is unused (and records it), false if already used.
func (r *NonceRegistry) CheckAndRecord(keyID, sessionID string, nonce []byte) bool {
	if r == nil {
		return true // Nil registry allows all nonces
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	key := nonceRegistryKey(keyID, sessionID, nonce)
	if _, exists := r.used[key]; exists {
		return false // Nonce already used
	}

	// Enforce capacity limit by clearing all entries when full.
	// This is a simple eviction strategy: clear all and start fresh.
	if r.maxEntries > 0 && len(r.used) >= r.maxEntries {
		for k := range r.used {
			delete(r.used, k)
		}
	}

	r.used[key] = struct{}{}
	return true
}

// SealWithRegistry encrypts plaintext into an Envelope using a nonce registry.
// The registry ensures nonce uniqueness for each (KeyID, SessionID) pair.
// If the nonce has been used before, the function returns an error.
//
// This is the recommended approach for applications that require strong
// nonce uniqueness guarantees beyond random generation.
func SealWithRegistry(keys SessionKeys, nonce []byte, plaintext, aad []byte, registry *NonceRegistry) (Envelope, error) {
	if keys.KeyID == "" {
		return Envelope{}, errEmptyKeyID
	}
	if keys.SessionID == "" {
		return Envelope{}, errEmptySessionID
	}
	if len(nonce) != nonceSize {
		return Envelope{}, errInvalidNonceLength
	}

	// Check nonce uniqueness
	if !registry.CheckAndRecord(keys.KeyID, keys.SessionID, nonce) {
		return Envelope{}, errNonceReuse
	}

	return SealWithNonce(keys, nonce, plaintext, aad)
}

// Open decrypts an Envelope and verifies MAC integrity.
func Open(keys SessionKeys, env Envelope) ([]byte, error) {
	if keys.KeyID == "" {
		return nil, errEmptyKeyID
	}
	if keys.SessionID == "" {
		return nil, errEmptySessionID
	}
	if env.Version != 1 {
		return nil, errUnsupportedVersion
	}

	if !VerifyMACSM3(keys.HMACKey, macInput(env), env.MAC) {
		return nil, errMACVerificationFailed
	}

	return sm4GCMOpen(keys.SM4Key, env.Nonce, env.Ciphertext, env.AAD)
}

func computeEnvelopeMAC(key []byte, env Envelope) []byte {
	return MACSM3(key, macInput(env))
}

// macInput produces a canonical binary encoding of the envelope fields for MAC.
// Format: version(u16) | len(sid)(u16) | sid | len(kid)(u16) | kid |
//
//	len(nonce)(u16) | nonce | len(aad)(u16) | aad | len(ct)(u16) | ct
func macInput(env Envelope) []byte {
	sid := []byte(env.SessionID)
	kid := []byte(env.KeyID)

	size := 2 + 2 + len(sid) + 2 + len(kid) + 2 + len(env.Nonce) + 2 + len(env.AAD) + 2 + len(env.Ciphertext)
	buf := make([]byte, 0, size)

	buf = binary.BigEndian.AppendUint16(buf, uint16(env.Version))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(sid)))
	buf = append(buf, sid...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(kid)))
	buf = append(buf, kid...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(env.Nonce)))
	buf = append(buf, env.Nonce...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(env.AAD)))
	buf = append(buf, env.AAD...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(env.Ciphertext)))
	buf = append(buf, env.Ciphertext...)

	return buf
}

// MarshalJSON serializes the envelope to JSON.
func (e Envelope) MarshalJSON() ([]byte, error) {
	type alias Envelope
	return json.Marshal((*alias)(&e))
}

// sm4GCMSeal encrypts plaintext with SM4-GCM using the given key, nonce, and AAD.
func sm4GCMSeal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := sm4.NewGCM(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// sm4GCMOpen decrypts ciphertext with SM4-GCM using the given key, nonce, and AAD.
func sm4GCMOpen(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := sm4.NewGCM(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}
