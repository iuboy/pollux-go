package test

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	polluxSM4 "github.com/iuboy/pollux-go/sm4"
)

func TestBlackBox_SM4_NewCipher_InvalidKeySize(t *testing.T) {
	_, err := polluxSM4.NewCipher(make([]byte, 15))
	if err == nil {
		t.Error("15-byte key should be rejected")
	}
	_, err = polluxSM4.NewCipher(make([]byte, 17))
	if err == nil {
		t.Error("17-byte key should be rejected")
	}
}

func TestBlackBox_SM4_NewCipher_ValidKeySize(t *testing.T) {
	key, err := polluxSM4.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	block, err := polluxSM4.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	if block.BlockSize() != polluxSM4.BlockSize {
		t.Errorf("BlockSize: got %d, want %d", block.BlockSize(), polluxSM4.BlockSize)
	}
}

func TestBlackBox_SM4_GCM_Roundtrip(t *testing.T) {
	key, err := polluxSM4.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	aead, err := polluxSM4.NewGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	plaintext := []byte("SM4-GCM roundtrip test payload")

	ct := aead.Seal(nil, nonce, plaintext, nil)
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Error("GCM roundtrip mismatch")
	}
}

func TestBlackBox_SM4_GCM_EmptyPlaintext(t *testing.T) {
	key, err := polluxSM4.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	aead, err := polluxSM4.NewGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)

	ct := aead.Seal(nil, nonce, nil, nil)
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != 0 {
		t.Errorf("empty GCM roundtrip: got %d bytes, want 0", len(pt))
	}
}

func TestBlackBox_SM4_GCM_TamperedCiphertext(t *testing.T) {
	key, err := polluxSM4.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	aead, err := polluxSM4.NewGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)

	ct := aead.Seal(nil, nonce, []byte("secret data"), nil)
	ct[0] ^= 0xff

	_, err = aead.Open(nil, nonce, ct, nil)
	if err == nil {
		t.Error("tampered ciphertext should fail authentication")
	}
}

func TestBlackBox_SM4_GCM_WrongNonce(t *testing.T) {
	key, err := polluxSM4.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	aead, err := polluxSM4.NewGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce1 := make([]byte, aead.NonceSize())
	nonce2 := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce1)
	_, _ = rand.Read(nonce2)

	ct := aead.Seal(nil, nonce1, []byte("test"), nil)
	_, err = aead.Open(nil, nonce2, ct, nil)
	if err == nil {
		t.Error("wrong nonce should fail")
	}
}

func TestBlackBox_SM4_CTR_PartialBlock(t *testing.T) {
	key, err := polluxSM4.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	iv, err := polluxSM4.GenerateIV()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("7 bytes")

	block, _ := polluxSM4.NewCipher(key)
	stream := cipher.NewCTR(block, iv)
	ct := make([]byte, len(plaintext))
	stream.XORKeyStream(ct, plaintext)

	stream2 := cipher.NewCTR(block, iv)
	pt := make([]byte, len(plaintext))
	stream2.XORKeyStream(pt, ct)

	if !bytes.Equal(pt, plaintext) {
		t.Error("CTR partial block roundtrip mismatch")
	}
}

func TestBlackBox_SM4_CBC_Roundtrip(t *testing.T) {
	key, err := polluxSM4.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	iv, err := polluxSM4.GenerateIV()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("SM4 CBC mode roundtrip test")

	ct, err := polluxSM4.Encrypt(key, plaintext, polluxSM4.ModeCBC, iv)
	if err != nil {
		t.Fatalf("Encrypt CBC: %v", err)
	}
	pt, err := polluxSM4.Decrypt(key, ct, polluxSM4.ModeCBC, iv)
	if err != nil {
		t.Fatalf("Decrypt CBC: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Error("CBC roundtrip mismatch")
	}
}

func TestBlackBox_SM4_GCM_EncryptDecryptAPI(t *testing.T) {
	key, err := polluxSM4.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("SM4-GCM high-level API test")

	// GCM 模式 Encrypt 内部自动生成 nonce 并追加到密文前
	ct, err := polluxSM4.Encrypt(key, plaintext, polluxSM4.ModeGCM, nil)
	if err != nil {
		t.Fatalf("Encrypt GCM: %v", err)
	}
	pt, err := polluxSM4.Decrypt(key, ct, polluxSM4.ModeGCM, nil)
	if err != nil {
		t.Fatalf("Decrypt GCM: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Error("Encrypt/Decrypt GCM API roundtrip mismatch")
	}
}

func TestBlackBox_SM4_GenerateKey(t *testing.T) {
	k1, err := polluxSM4.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != 16 {
		t.Errorf("key length: got %d, want 16", len(k1))
	}
	k2, _ := polluxSM4.GenerateKey()
	if bytes.Equal(k1, k2) {
		t.Error("two generated keys should differ")
	}
}
