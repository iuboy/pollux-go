package test

import (
	"bytes"
	"crypto/rand"
	"testing"

	polluxQUICGM "github.com/iuboy/pollux-go/quicgm"
)

func mustGenerateSessionKeys(t *testing.T) polluxQUICGM.SessionKeys {
	t.Helper()
	keys, err := polluxQUICGM.GenerateSessionKeys(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateSessionKeys: %v", err)
	}
	return keys
}

func TestBlackBox_QUICGM_GenerateSessionKeys(t *testing.T) {
	keys := mustGenerateSessionKeys(t)
	if keys.KeyID == "" {
		t.Error("KeyID should not be empty")
	}
	if keys.SessionID == "" {
		t.Error("SessionID should not be empty")
	}
	if len(keys.HMACKey) != 32 {
		t.Errorf("HMACKey length: got %d, want 32", len(keys.HMACKey))
	}
	if len(keys.SM4Key) != 16 {
		t.Errorf("SM4Key length: got %d, want 16", len(keys.SM4Key))
	}
}

func TestBlackBox_QUICGM_GenerateSessionKeys_Unique(t *testing.T) {
	k1 := mustGenerateSessionKeys(t)
	k2 := mustGenerateSessionKeys(t)
	if k1.KeyID == k2.KeyID {
		t.Error("two calls should produce different KeyIDs")
	}
}

func TestBlackBox_QUICGM_Envelope_RoundTrip(t *testing.T) {
	keys := mustGenerateSessionKeys(t)
	plaintext := []byte("quicgm envelope black-box test")
	aad := []byte("aad-value")

	env, err := polluxQUICGM.Seal(keys, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if env.Version != 1 {
		t.Errorf("Version: got %d, want 1", env.Version)
	}
	if len(env.Ciphertext) == 0 {
		t.Error("Ciphertext should not be empty")
	}
	if len(env.Nonce) == 0 {
		t.Error("Nonce should not be empty")
	}
	if len(env.MAC) == 0 {
		t.Error("MAC should not be empty")
	}

	decrypted, err := polluxQUICGM.Open(keys, env)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("roundtrip: got %q, want %q", decrypted, plaintext)
	}
}

func TestBlackBox_QUICGM_Envelope_PayloadTamperRejected(t *testing.T) {
	keys := mustGenerateSessionKeys(t)
	env, _ := polluxQUICGM.Seal(keys, []byte("secret"), nil)

	env.Ciphertext[0] ^= 0xff
	_, err := polluxQUICGM.Open(keys, env)
	if err == nil {
		t.Error("tampered ciphertext should fail MAC or AEAD verification")
	}
}

func TestBlackBox_QUICGM_Envelope_AADTamperRejected(t *testing.T) {
	keys := mustGenerateSessionKeys(t)
	env, _ := polluxQUICGM.Seal(keys, []byte("secret"), []byte("aad-original"))

	env.AAD = []byte("aad-tampered")
	_, err := polluxQUICGM.Open(keys, env)
	if err == nil {
		t.Error("tampered AAD should fail")
	}
}

func TestBlackBox_QUICGM_Envelope_WrongKey(t *testing.T) {
	keys1 := mustGenerateSessionKeys(t)
	keys2 := mustGenerateSessionKeys(t)

	env, _ := polluxQUICGM.Seal(keys1, []byte("secret"), nil)
	_, err := polluxQUICGM.Open(keys2, env)
	if err == nil {
		t.Error("wrong key should fail")
	}
}

func TestBlackBox_QUICGM_MACSM3_RoundTrip(t *testing.T) {
	key := []byte("mac-test-key-32-bytes-long-xxxxx")
	data := []byte("data to authenticate")

	mac := polluxQUICGM.MACSM3(key, data)
	if len(mac) != 32 {
		t.Errorf("MAC length: got %d, want 32", len(mac))
	}
	if !polluxQUICGM.VerifyMACSM3(key, data, mac) {
		t.Error("VerifyMACSM3 should accept correct MAC")
	}
}

func TestBlackBox_QUICGM_MACSM3_WrongMAC(t *testing.T) {
	key := []byte("mac-test-key-32-bytes-long-xxxxx")
	data := []byte("data to authenticate")
	wrongMAC := make([]byte, 32)

	if polluxQUICGM.VerifyMACSM3(key, data, wrongMAC) {
		t.Error("should reject wrong MAC")
	}
}

func TestBlackBox_QUICGM_MACSM3_WrongData(t *testing.T) {
	key := []byte("mac-test-key-32-bytes-long-xxxxx")
	mac := polluxQUICGM.MACSM3(key, []byte("original"))

	if polluxQUICGM.VerifyMACSM3(key, []byte("tampered"), mac) {
		t.Error("should reject wrong data")
	}
}

func TestBlackBox_QUICGM_SealWithNonce_ValidNonce(t *testing.T) {
	keys := mustGenerateSessionKeys(t)
	nonce := make([]byte, 12)
	plaintext := []byte("test plaintext")
	aad := []byte("metadata")

	env, err := polluxQUICGM.SealWithNonce(keys, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("SealWithNonce failed: %v", err)
	}

	decrypted, err := polluxQUICGM.Open(keys, env)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestBlackBox_QUICGM_SealWithNonce_InvalidNonceLength(t *testing.T) {
	keys := mustGenerateSessionKeys(t)
	invalidNonce := make([]byte, 8) // Wrong length

	_, err := polluxQUICGM.SealWithNonce(keys, invalidNonce, []byte("x"), nil)
	if err == nil {
		t.Error("invalid nonce length should fail")
	}
}

func TestBlackBox_QUICGM_NonceRegistry_ReuseDetection(t *testing.T) {
	registry := polluxQUICGM.NewNonceRegistry()
	keys := mustGenerateSessionKeys(t)
	nonce := make([]byte, 12)
	plaintext := []byte("test plaintext")

	// First use should succeed
	_, err := polluxQUICGM.SealWithRegistry(keys, nonce, plaintext, nil, registry)
	if err != nil {
		t.Fatalf("first SealWithRegistry failed: %v", err)
	}

	// Second use with same nonce should fail
	_, err = polluxQUICGM.SealWithRegistry(keys, nonce, plaintext, nil, registry)
	if err == nil {
		t.Error("nonce reuse should fail")
	}
}

func TestBlackBox_QUICGM_NonceRegistry_DifferentSessionsCanReuseNonce(t *testing.T) {
	registry := polluxQUICGM.NewNonceRegistry()
	keys := mustGenerateSessionKeys(t)
	nonce := make([]byte, 12)
	plaintext := []byte("test plaintext")

	// Seal with first session
	_, err := polluxQUICGM.SealWithRegistry(keys, nonce, plaintext, nil, registry)
	if err != nil {
		t.Fatalf("first SealWithRegistry failed: %v", err)
	}

	// Same nonce with different session should succeed
	keys2 := keys
	keys2.SessionID = "different-session-id"
	_, err = polluxQUICGM.SealWithRegistry(keys2, nonce, plaintext, nil, registry)
	if err != nil {
		t.Fatalf("SealWithRegistry with different session failed: %v", err)
	}
}

func TestBlackBox_QUICGM_NonceRegistry_DifferentKeysCanReuseNonce(t *testing.T) {
	registry := polluxQUICGM.NewNonceRegistry()
	keys := mustGenerateSessionKeys(t)
	nonce := make([]byte, 12)
	plaintext := []byte("test plaintext")

	// Seal with first key
	_, err := polluxQUICGM.SealWithRegistry(keys, nonce, plaintext, nil, registry)
	if err != nil {
		t.Fatalf("first SealWithRegistry failed: %v", err)
	}

	// Same nonce with different key should succeed
	keys2 := keys
	keys2.KeyID = "different-key-id"
	_, err = polluxQUICGM.SealWithRegistry(keys2, nonce, plaintext, nil, registry)
	if err != nil {
		t.Fatalf("SealWithRegistry with different key failed: %v", err)
	}
}

func TestBlackBox_QUICGM_NonceRegistry_NilRegistryAllowsAll(t *testing.T) {
	keys := mustGenerateSessionKeys(t)
	nonce := make([]byte, 12)
	plaintext := []byte("test plaintext")

	// Nil registry should allow all nonces
	_, err := polluxQUICGM.SealWithRegistry(keys, nonce, plaintext, nil, nil)
	if err != nil {
		t.Fatalf("SealWithRegistry with nil registry failed: %v", err)
	}

	// Same nonce should also succeed with nil registry
	_, err = polluxQUICGM.SealWithRegistry(keys, nonce, plaintext, nil, nil)
	if err != nil {
		t.Fatalf("second SealWithRegistry with nil registry failed: %v", err)
	}
}

func TestBlackBox_QUICGM_NonceRegistry_EndToEnd(t *testing.T) {
	registry := polluxQUICGM.NewNonceRegistry()
	keys := mustGenerateSessionKeys(t)
	nonce := make([]byte, 12)
	plaintext := []byte("test plaintext with nonce registry")
	aad := []byte("metadata")

	// Seal with registry
	env, err := polluxQUICGM.SealWithRegistry(keys, nonce, plaintext, aad, registry)
	if err != nil {
		t.Fatalf("SealWithRegistry failed: %v", err)
	}

	// Open should work normally
	decrypted, err := polluxQUICGM.Open(keys, env)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}
