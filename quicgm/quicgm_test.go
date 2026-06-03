package quicgm

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestGenerateSessionKeys(t *testing.T) {
	keys, err := GenerateSessionKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if keys.KeyID == "" {
		t.Error("KeyID should not be empty")
	}
	if keys.SessionID == "" {
		t.Error("SessionID should not be empty")
	}
	if len(keys.HMACKey) != 32 {
		t.Errorf("HMACKey: got %d bytes, want 32", len(keys.HMACKey))
	}
	if len(keys.SM4Key) != 16 {
		t.Errorf("SM4Key: got %d bytes, want 16", len(keys.SM4Key))
	}
}

func TestMACSM3_Deterministic(t *testing.T) {
	key := make([]byte, 32)
	data := []byte("test data")
	mac1 := MACSM3(key, data)
	mac2 := MACSM3(key, data)
	if !bytes.Equal(mac1, mac2) {
		t.Error("MAC should be deterministic")
	}
}

func TestVerifyMACSM3_CorrectMAC(t *testing.T) {
	key := make([]byte, 32)
	data := []byte("test data")
	mac := MACSM3(key, data)
	if !VerifyMACSM3(key, data, mac) {
		t.Error("correct MAC should verify")
	}
}

func TestVerifyMACSM3_WrongMAC(t *testing.T) {
	key := make([]byte, 32)
	data := []byte("test data")
	wrongMAC := make([]byte, 32)
	if VerifyMACSM3(key, data, wrongMAC) {
		t.Error("wrong MAC should not verify")
	}
}

func TestVerifyMACSM3_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1
	data := []byte("test data")
	mac := MACSM3(key1, data)
	if VerifyMACSM3(key2, data, mac) {
		t.Error("wrong key should not verify")
	}
}

func TestEnvelope_RoundTrip(t *testing.T) {
	keys, _ := GenerateSessionKeys(rand.Reader)
	pt := []byte("hello quicgm envelope")
	aad := []byte("metadata")

	env, err := Seal(keys, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	if env.Version != 1 {
		t.Errorf("Version: got %d, want 1", env.Version)
	}
	if len(env.Nonce) != 12 {
		t.Errorf("Nonce: got %d bytes, want 12", len(env.Nonce))
	}

	got, err := Open(keys, env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Error("roundtrip mismatch")
	}
}

func TestEnvelope_PayloadTamper(t *testing.T) {
	keys, _ := GenerateSessionKeys(rand.Reader)
	env, _ := Seal(keys, []byte("secret"), nil)
	env.Ciphertext[0] ^= 0xff
	_, err := Open(keys, env)
	if err == nil {
		t.Error("tampered payload should fail")
	}
}

func TestEnvelope_WrongKey(t *testing.T) {
	keys1, _ := GenerateSessionKeys(rand.Reader)
	keys2, _ := GenerateSessionKeys(rand.Reader)
	env, _ := Seal(keys1, []byte("secret"), nil)
	_, err := Open(keys2, env)
	if err == nil {
		t.Error("wrong key should fail")
	}
}

func TestEnvelope_EmptyKeyID(t *testing.T) {
	keys := SessionKeys{HMACKey: make([]byte, 32), SM4Key: make([]byte, 16)}
	_, err := Seal(keys, []byte("x"), nil)
	if err == nil {
		t.Error("empty KeyID should fail")
	}
}

func TestEnvelope_EmptySessionID(t *testing.T) {
	keys := SessionKeys{KeyID: "test", HMACKey: make([]byte, 32), SM4Key: make([]byte, 16)}
	_, err := Seal(keys, []byte("x"), nil)
	if err == nil {
		t.Error("empty SessionID should fail")
	}
}

func TestSealWithNonce_ValidNonce(t *testing.T) {
	keys, _ := GenerateSessionKeys(rand.Reader)
	nonce := make([]byte, 12)
	pt := []byte("test plaintext")
	aad := []byte("metadata")

	env, err := SealWithNonce(keys, nonce, pt, aad)
	if err != nil {
		t.Fatalf("SealWithNonce failed: %v", err)
	}

	got, err := Open(keys, env)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Error("plaintext mismatch")
	}
}

func TestSealWithNonce_InvalidNonceLength(t *testing.T) {
	keys, _ := GenerateSessionKeys(rand.Reader)
	nonce := make([]byte, 8) // Wrong length

	_, err := SealWithNonce(keys, nonce, []byte("x"), nil)
	if err == nil {
		t.Error("invalid nonce length should fail")
	}
}

func TestNonceRegistry_ReuseDetection(t *testing.T) {
	registry := NewNonceRegistry()
	keys, _ := GenerateSessionKeys(rand.Reader)
	nonce := make([]byte, 12)
	pt := []byte("test plaintext")

	// First use should succeed
	_, err := SealWithRegistry(keys, nonce, pt, nil, registry)
	if err != nil {
		t.Fatalf("first SealWithRegistry failed: %v", err)
	}

	// Second use with same nonce should fail
	_, err = SealWithRegistry(keys, nonce, pt, nil, registry)
	if err == nil {
		t.Error("nonce reuse should fail")
	}
	if err != errNonceReuse {
		t.Errorf("got error %v, want %v", err, errNonceReuse)
	}
}

func TestNonceRegistry_DifferentSessionsCanReuseNonce(t *testing.T) {
	registry := NewNonceRegistry()
	keys, _ := GenerateSessionKeys(rand.Reader)
	nonce := make([]byte, 12)
	pt := []byte("test plaintext")

	// Seal with first session
	_, err := SealWithRegistry(keys, nonce, pt, nil, registry)
	if err != nil {
		t.Fatalf("first SealWithRegistry failed: %v", err)
	}

	// Same nonce with different session should succeed
	keys2 := keys
	keys2.SessionID = "different-session"
	_, err = SealWithRegistry(keys2, nonce, pt, nil, registry)
	if err != nil {
		t.Fatalf("SealWithRegistry with different session failed: %v", err)
	}
}

func TestNonceRegistry_DifferentKeysCanReuseNonce(t *testing.T) {
	registry := NewNonceRegistry()
	keys, _ := GenerateSessionKeys(rand.Reader)
	nonce := make([]byte, 12)
	pt := []byte("test plaintext")

	// Seal with first key
	_, err := SealWithRegistry(keys, nonce, pt, nil, registry)
	if err != nil {
		t.Fatalf("first SealWithRegistry failed: %v", err)
	}

	// Same nonce with different key should succeed
	keys2 := keys
	keys2.KeyID = "different-key"
	_, err = SealWithRegistry(keys2, nonce, pt, nil, registry)
	if err != nil {
		t.Fatalf("SealWithRegistry with different key failed: %v", err)
	}
}

func TestNonceRegistry_NilRegistryAllowsAll(t *testing.T) {
	keys, _ := GenerateSessionKeys(rand.Reader)
	nonce := make([]byte, 12)
	pt := []byte("test plaintext")

	// Nil registry should allow all nonces
	_, err := SealWithRegistry(keys, nonce, pt, nil, nil)
	if err != nil {
		t.Fatalf("SealWithRegistry with nil registry failed: %v", err)
	}

	// Same nonce should also succeed with nil registry
	_, err = SealWithRegistry(keys, nonce, pt, nil, nil)
	if err != nil {
		t.Fatalf("second SealWithRegistry with nil registry failed: %v", err)
	}
}

func TestNonceRegistry_ConcurrentUse(t *testing.T) {
	registry := NewNonceRegistry()
	keys, _ := GenerateSessionKeys(rand.Reader)
	nonce := make([]byte, 12)
	pt := []byte("test plaintext")

	// First use should succeed
	_, err := SealWithRegistry(keys, nonce, pt, nil, registry)
	if err != nil {
		t.Fatalf("first SealWithRegistry failed: %v", err)
	}

	// Test concurrent access (should not panic)
	done := make(chan bool)
	go func() {
		_, _ = SealWithRegistry(keys, nonce, pt, nil, registry)
		done <- true
	}()
	go func() {
		_, _ = SealWithRegistry(keys, nonce, pt, nil, registry)
		done <- true
	}()
	<-done
	<-done
}
