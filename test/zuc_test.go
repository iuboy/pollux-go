package test

import (
	"bytes"
	"crypto/rand"
	"testing"

	polluxZUC "github.com/ycq/pollux/zuc"
)

func TestBlackBox_ZUC_NewCipher_EncryptDecrypt(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	stream, err := polluxZUC.NewCipher(key, iv)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	plaintext := []byte("ZUC stream cipher test data")
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	// 解密
	stream2, _ := polluxZUC.NewCipher(key, iv)
	decrypted := make([]byte, len(ciphertext))
	stream2.XORKeyStream(decrypted, ciphertext)

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("ZUC roundtrip: got %x, want %x", decrypted, plaintext)
	}
}

func TestBlackBox_ZUC_NewCipher_InvalidKeySize(t *testing.T) {
	_, err := polluxZUC.NewCipher([]byte{1, 2, 3}, []byte{1, 2, 3})
	if err == nil {
		t.Error("should reject invalid key size")
	}
}

func TestBlackBox_ZUC_NewEEACipher(t *testing.T) {
	key := make([]byte, 16)
	_, _ = rand.Read(key)

	stream, err := polluxZUC.NewEEACipher(key, 0x12345678, 5, 0)
	if err != nil {
		t.Fatalf("NewEEACipher: %v", err)
	}

	plaintext := []byte("EEA encryption test")
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	stream2, _ := polluxZUC.NewEEACipher(key, 0x12345678, 5, 0)
	decrypted := make([]byte, len(ciphertext))
	stream2.XORKeyStream(decrypted, ciphertext)

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("EEA roundtrip mismatch")
	}
}

func TestBlackBox_ZUC_EEA_DifferentParams(t *testing.T) {
	key := make([]byte, 16)
	_, _ = rand.Read(key)

	stream1, _ := polluxZUC.NewEEACipher(key, 0, 1, 0)
	stream2, _ := polluxZUC.NewEEACipher(key, 0, 2, 0)

	pt := []byte("different bearer")
	ct1 := make([]byte, len(pt))
	ct2 := make([]byte, len(pt))
	stream1.XORKeyStream(ct1, pt)
	stream2.XORKeyStream(ct2, pt)

	if bytes.Equal(ct1, ct2) {
		t.Error("different bearers should produce different ciphertext")
	}
}

func TestBlackBox_ZUC_NewHash_MAC(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	hash, err := polluxZUC.NewHash(key, iv)
	if err != nil {
		t.Fatalf("NewHash: %v", err)
	}

	data := []byte("EIA integrity test")
	_, _ = hash.Write(data)
	mac := hash.Sum(nil)

	if len(mac) == 0 {
		t.Error("MAC should not be empty")
	}
	// 典型 MAC 长度为 4 字节
	if len(mac) != 4 {
		t.Logf("MAC length: %d bytes", len(mac))
	}
}

func TestBlackBox_ZUC_NewHash_Deterministic(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)
	data := []byte("deterministic test")

	h1, _ := polluxZUC.NewHash(key, iv)
	_, _ = h1.Write(data)
	mac1 := h1.Sum(nil)

	h2, _ := polluxZUC.NewHash(key, iv)
	_, _ = h2.Write(data)
	mac2 := h2.Sum(nil)

	if !bytes.Equal(mac1, mac2) {
		t.Error("same key/iv/data should produce same MAC")
	}
}

func TestBlackBox_ZUC_EIA_DifferentData(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	h1, _ := polluxZUC.NewHash(key, iv)
	_, _ = h1.Write([]byte("data A"))
	mac1 := h1.Sum(nil)

	h2, _ := polluxZUC.NewHash(key, iv)
	_, _ = h2.Write([]byte("data B"))
	mac2 := h2.Sum(nil)

	if bytes.Equal(mac1, mac2) {
		t.Error("different data should produce different MAC")
	}
}

func TestBlackBox_ZUC_MAC(t *testing.T) {
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	data := []byte("MAC convenience function test")

	mac, err := polluxZUC.MAC(key, 0, 1, 0, data)
	if err != nil {
		t.Fatalf("MAC: %v", err)
	}
	if len(mac) == 0 {
		t.Error("MAC should not be empty")
	}
}

func TestBlackBox_ZUC_Encrypt(t *testing.T) {
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	plaintext := []byte("ZUC Encrypt convenience test")

	ct, err := polluxZUC.Encrypt(key, 0, 1, 0, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(ct) != len(plaintext) {
		t.Errorf("ciphertext length: got %d, want %d", len(ct), len(plaintext))
	}
	if bytes.Equal(ct, plaintext) {
		t.Error("ciphertext should not equal plaintext")
	}

	// 解密验证
	pt, err := polluxZUC.Encrypt(key, 0, 1, 0, ct)
	if err != nil {
		t.Fatalf("Encrypt (decrypt): %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Error("roundtrip mismatch")
	}
}
