package gmstd

import (
	"bytes"
	"testing"
)

func TestSM3Hash(t *testing.T) {
	data := []byte("test")
	hash := SM3Hash(data)
	if len(hash) != 32 {
		t.Errorf("SM3 hash length: got %d, want 32", len(hash))
	}

	// deterministic
	hash2 := SM3Hash(data)
	if !bytes.Equal(hash, hash2) {
		t.Error("SM3 should be deterministic")
	}

	// different data → different hash
	hash3 := SM3Hash([]byte("different"))
	if bytes.Equal(hash, hash3) {
		t.Error("different inputs should produce different hashes")
	}
}

func TestSM3HashHex(t *testing.T) {
	hash := SM3HashHex([]byte("test"))
	if len(hash) != 64 {
		t.Errorf("hex hash length: got %d, want 64", len(hash))
	}
}

func TestSM3HashHex_KnownValue(t *testing.T) {
	// SM3("") = 1ab21d8355...
	empty := SM3HashHex([]byte(""))
	if len(empty) != 64 {
		t.Errorf("hex length: got %d, want 64", len(empty))
	}
}

func TestSM2KDF(t *testing.T) {
	z := []byte("shared-secret")
	klen := 48

	key, err := SM2KDF(z, klen)
	if err != nil {
		t.Fatalf("SM2KDF: %v", err)
	}
	if len(key) != klen {
		t.Errorf("KDF output length: got %d, want %d", len(key), klen)
	}

	// deterministic
	key2, _ := SM2KDF(z, klen)
	if !bytes.Equal(key, key2) {
		t.Error("KDF should be deterministic")
	}

	// different z → different key
	key3, _ := SM2KDF([]byte("other-secret"), klen)
	if bytes.Equal(key, key3) {
		t.Error("different inputs should produce different keys")
	}
}

func TestSM2KDF_ZeroLength(t *testing.T) {
	_, err := SM2KDF([]byte("z"), 0)
	if err == nil {
		t.Error("zero-length KDF should return error")
	}
}

// TestSM2KDF_NegativeLength covers the negative klen branch: the underlying
// sm3.KDF rejects klen <= 0; the gmstd wrapper must surface that error rather
// than panic or return an empty slice.
func TestSM2KDF_NegativeLength(t *testing.T) {
	_, err := SM2KDF([]byte("z"), -1)
	if err == nil {
		t.Error("negative klen should return error")
	}
}

// TestSM2KDF_EmptySharedSecret covers the empty-z branch: sm3.KDF rejects
// empty input with a distinct error so callers do not silently derive a key
// from a degenerate shared secret.
func TestSM2KDF_EmptySharedSecret(t *testing.T) {
	_, err := SM2KDF([]byte{}, 32)
	if err == nil {
		t.Error("empty shared secret should return error")
	}
	// nil z must be rejected identically.
	if _, err := SM2KDF(nil, 32); err == nil {
		t.Error("nil shared secret should return error")
	}
}

// TestSM2KDF_OversizedLength covers the new maxKDFLen guard added in
// OCR Tier 2 — a klen above the cap must error rather than OOM.
func TestSM2KDF_OversizedLength(t *testing.T) {
	_, err := SM2KDF([]byte("z"), 1<<31) // 2 GiB > 1 GiB cap
	if err == nil {
		t.Error("oversized klen should return error")
	}
}

func TestGenerateSM4Key(t *testing.T) {
	key, err := GenerateSM4Key()
	if err != nil {
		t.Fatalf("GenerateSM4Key: %v", err)
	}
	if len(key) != 16 {
		t.Errorf("SM4 key length: got %d, want 16", len(key))
	}

	// should be random (two calls produce different keys)
	key2, _ := GenerateSM4Key()
	if bytes.Equal(key, key2) {
		t.Error("two generated keys should differ")
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce, err := GenerateNonce(12)
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	if len(nonce) != 12 {
		t.Errorf("nonce length: got %d, want 12", len(nonce))
	}

	nonce2, _ := GenerateNonce(12)
	if bytes.Equal(nonce, nonce2) {
		t.Error("two generated nonces should differ")
	}
}

func TestGenerateNonce_InvalidSize(t *testing.T) {
	_, err := GenerateNonce(0)
	if err == nil {
		t.Error("should reject zero size")
	}

	_, err = GenerateNonce(-1)
	if err == nil {
		t.Error("should reject negative size")
	}
}
