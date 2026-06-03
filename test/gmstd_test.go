package test

import (
	"bytes"
	"crypto/rand"
	"testing"

	polluxGmstd "github.com/ycq/pollux/gmstd"
	polluxSM2 "github.com/ycq/pollux/sm2"
)

func TestBlackBox_SM3Hash(t *testing.T) {
	data := []byte("gmstd SM3Hash test")
	hash := polluxGmstd.SM3Hash(data)
	if len(hash) != 32 {
		t.Errorf("SM3Hash length: got %d, want 32", len(hash))
	}
}

func TestBlackBox_SM3Hash_Deterministic(t *testing.T) {
	data := []byte("deterministic")
	h1 := polluxGmstd.SM3Hash(data)
	h2 := polluxGmstd.SM3Hash(data)
	if !bytes.Equal(h1, h2) {
		t.Error("SM3Hash should be deterministic")
	}
}

func TestBlackBox_SM3Hash_DifferentInput(t *testing.T) {
	h1 := polluxGmstd.SM3Hash([]byte("input A"))
	h2 := polluxGmstd.SM3Hash([]byte("input B"))
	if bytes.Equal(h1, h2) {
		t.Error("different inputs should produce different hashes")
	}
}

func TestBlackBox_SM3HashHex(t *testing.T) {
	data := []byte("gmstd SM3HashHex test")
	hex := polluxGmstd.SM3HashHex(data)
	if len(hex) != 64 {
		t.Errorf("SM3HashHex length: got %d, want 64", len(hex))
	}
}

func TestBlackBox_SM3HashForPublicKey(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := polluxGmstd.SM3HashForPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("SM3HashForPublicKey: %v", err)
	}
	if len(hash) != 32 {
		t.Errorf("hash length: got %d, want 32", len(hash))
	}
}

func TestBlackBox_SM3HashForPublicKey_DifferentKeys(t *testing.T) {
	priv1, _ := polluxSM2.GenerateKey(rand.Reader)
	priv2, _ := polluxSM2.GenerateKey(rand.Reader)

	h1, _ := polluxGmstd.SM3HashForPublicKey(&priv1.PublicKey)
	h2, _ := polluxGmstd.SM3HashForPublicKey(&priv2.PublicKey)

	if bytes.Equal(h1, h2) {
		t.Error("different keys should produce different hashes")
	}
}

func TestBlackBox_ComputeSM2UserID(t *testing.T) {
	priv, _ := polluxSM2.GenerateKey(rand.Reader)

	uid, err := polluxGmstd.ComputeSM2UserID(&priv.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSM2UserID: %v", err)
	}
	if len(uid) == 0 {
		t.Error("UID should not be empty")
	}
}

func TestBlackBox_ComputeSM2UserID_DefaultUID(t *testing.T) {
	priv, _ := polluxSM2.GenerateKey(rand.Reader)
	uid, _ := polluxGmstd.ComputeSM2UserID(&priv.PublicKey)

	// 相同公钥应返回相同 UID
	uid2, _ := polluxGmstd.ComputeSM2UserID(&priv.PublicKey)
	if !bytes.Equal(uid, uid2) {
		t.Error("same key should produce same UID")
	}
}

func TestBlackBox_GenerateSM4Key(t *testing.T) {
	key, err := polluxGmstd.GenerateSM4Key()
	if err != nil {
		t.Fatalf("GenerateSM4Key: %v", err)
	}
	if len(key) != 16 {
		t.Errorf("SM4 key length: got %d, want 16", len(key))
	}
}

func TestBlackBox_GenerateSM4Key_Unique(t *testing.T) {
	k1, _ := polluxGmstd.GenerateSM4Key()
	k2, _ := polluxGmstd.GenerateSM4Key()
	if bytes.Equal(k1, k2) {
		t.Error("two generated keys should be different")
	}
}

func TestBlackBox_GenerateNonce(t *testing.T) {
	nonce, err := polluxGmstd.GenerateNonce(16)
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	if len(nonce) != 16 {
		t.Errorf("nonce length: got %d, want 16", len(nonce))
	}
}

func TestBlackBox_GenerateNonce_DifferentSizes(t *testing.T) {
	for _, size := range []int{8, 12, 16, 32} {
		nonce, err := polluxGmstd.GenerateNonce(size)
		if err != nil {
			t.Errorf("GenerateNonce(%d): %v", size, err)
		}
		if len(nonce) != size {
			t.Errorf("nonce size %d: got %d", size, len(nonce))
		}
	}
}

func TestBlackBox_GenerateNonce_InvalidSize(t *testing.T) {
	_, err := polluxGmstd.GenerateNonce(0)
	if err == nil {
		t.Error("should reject size 0")
	}
	_, err = polluxGmstd.GenerateNonce(-1)
	if err == nil {
		t.Error("should reject negative size")
	}
}

func TestBlackBox_SM2KDF(t *testing.T) {
	z := make([]byte, 32)
	_, _ = rand.Read(z)

	derived, err := polluxGmstd.SM2KDF(z, 32)
	if err != nil {
		t.Fatalf("SM2KDF: %v", err)
	}
	if len(derived) != 32 {
		t.Errorf("SM2KDF length: got %d, want 32", len(derived))
	}
}

func TestBlackBox_SM2KDF_ZeroLength(t *testing.T) {
	z := make([]byte, 32)
	_, _ = rand.Read(z)

	_, err := polluxGmstd.SM2KDF(z, 0)
	if err == nil {
		t.Error("SM2KDF(0) should return error")
	}
}

func TestBlackBox_SM2KDF_DifferentLengths(t *testing.T) {
	z := make([]byte, 32)
	_, _ = rand.Read(z)

	d16, err := polluxGmstd.SM2KDF(z, 16)
	if err != nil {
		t.Fatalf("SM2KDF(16): %v", err)
	}
	d48, err := polluxGmstd.SM2KDF(z, 48)
	if err != nil {
		t.Fatalf("SM2KDF(48): %v", err)
	}

	if len(d16) != 16 || len(d48) != 48 {
		t.Errorf("SM2KDF lengths: got %d and %d", len(d16), len(d48))
	}
	// d48 的前 16 字节应与 d16 相同
	if !bytes.Equal(d16, d48[:16]) {
		t.Error("SM2KDF prefix mismatch")
	}
}

func TestBlackBox_SM2KDF_Deterministic(t *testing.T) {
	z := []byte("SM2 KDF determinism test input")

	d1, err := polluxGmstd.SM2KDF(z, 32)
	if err != nil {
		t.Fatalf("SM2KDF: %v", err)
	}
	d2, _ := polluxGmstd.SM2KDF(z, 32)

	if !bytes.Equal(d1, d2) {
		t.Error("SM2KDF should be deterministic")
	}
}
