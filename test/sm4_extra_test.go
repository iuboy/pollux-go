package test

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	polluxSM4 "github.com/ycq/pollux/sm4"
)

// ========== CMAC ==========

func TestBlackBox_SM4_CMAC(t *testing.T) {
	key, _ := polluxSM4.GenerateKey()
	data := []byte("SM4-CMAC black-box test")

	mac, err := polluxSM4.ComputeCMAC(key, data)
	if err != nil {
		t.Fatalf("ComputeCMAC: %v", err)
	}
	if len(mac) == 0 {
		t.Fatal("CMAC should not be empty")
	}
}

func TestBlackBox_SM4_VerifyCMAC(t *testing.T) {
	key, _ := polluxSM4.GenerateKey()
	data := []byte("CMAC verify test")

	mac, _ := polluxSM4.ComputeCMAC(key, data)

	if !polluxSM4.VerifyCMAC(key, data, mac) {
		t.Error("VerifyCMAC should accept valid MAC")
	}
	if polluxSM4.VerifyCMAC(key, data, []byte("wrong mac")) {
		t.Error("VerifyCMAC should reject invalid MAC")
	}
	if polluxSM4.VerifyCMAC(key, []byte("wrong data"), mac) {
		t.Error("VerifyCMAC should reject wrong data")
	}
}

func TestBlackBox_SM4_NewCMACHash(t *testing.T) {
	key, _ := polluxSM4.GenerateKey()
	h, err := polluxSM4.NewCMACHash(key)
	if err != nil {
		t.Fatalf("NewCMACHash: %v", err)
	}

	h.Write([]byte("part1"))
	h.Write([]byte("part2"))
	mac := h.Sum(nil)

	if !polluxSM4.VerifyCMAC(key, []byte("part1part2"), mac) {
		t.Error("streaming CMAC should match one-shot")
	}
}

func TestBlackBox_SM4_CMAC_DifferentKeys(t *testing.T) {
	k1, _ := polluxSM4.GenerateKey()
	k2, _ := polluxSM4.GenerateKey()
	data := []byte("same data")

	m1, _ := polluxSM4.ComputeCMAC(k1, data)
	m2, _ := polluxSM4.ComputeCMAC(k2, data)

	if bytes.Equal(m1, m2) {
		t.Error("different keys should produce different MACs")
	}
}

// ========== KeyWrap ==========

func TestBlackBox_SM4_KeyWrap_RoundTrip(t *testing.T) {
	kek := make([]byte, 16)
	plaintextKey := make([]byte, 32)
	_, _ = rand.Read(kek)
	_, _ = rand.Read(plaintextKey)

	wrapped, err := polluxSM4.KeyWrap(kek, plaintextKey)
	if err != nil {
		t.Fatalf("KeyWrap: %v", err)
	}
	if len(wrapped) == 0 {
		t.Fatal("wrapped key should not be empty")
	}

	unwrapped, err := polluxSM4.KeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("KeyUnwrap: %v", err)
	}
	if !bytes.Equal(unwrapped, plaintextKey) {
		t.Error("unwrapped key mismatch")
	}
}

func TestBlackBox_SM4_KeyWrap_WrongKEK(t *testing.T) {
	kek := make([]byte, 16)
	wrongKEK := make([]byte, 16)
	ptKey := make([]byte, 16)
	_, _ = rand.Read(kek)
	_, _ = rand.Read(wrongKEK)
	_, _ = rand.Read(ptKey)

	wrapped, _ := polluxSM4.KeyWrap(kek, ptKey)
	_, err := polluxSM4.KeyUnwrap(wrongKEK, wrapped)
	if err == nil {
		t.Error("KeyUnwrap with wrong KEK should fail")
	}
}

func TestBlackBox_SM4_KeyWrap_Tampered(t *testing.T) {
	kek := make([]byte, 16)
	ptKey := make([]byte, 16)
	_, _ = rand.Read(kek)
	_, _ = rand.Read(ptKey)

	wrapped, _ := polluxSM4.KeyWrap(kek, ptKey)
	wrapped[0] ^= 0xff
	_, err := polluxSM4.KeyUnwrap(kek, wrapped)
	if err == nil {
		t.Error("KeyUnwrap with tampered ciphertext should fail")
	}
}

func TestBlackBox_SM4_KeyWrap_InvalidKEK(t *testing.T) {
	_, err := polluxSM4.KeyWrap([]byte{1, 2, 3}, make([]byte, 16))
	if err == nil {
		t.Error("should reject invalid KEK size")
	}
}

// ========== CBC 流模式 ==========

func TestBlackBox_SM4_CBC_RoundTrip(t *testing.T) {
	key, _ := polluxSM4.GenerateKey()
	iv, _ := polluxSM4.GenerateIV()
	plaintext := []byte("SM4-CBC black-box test!!") // 24 bytes, needs padding to 32

	padded, err := polluxSM4.PKCS7Pad(plaintext, 16)
	if err != nil {
		t.Fatalf("PKCS7Pad: %v", err)
	}

	enc, err := polluxSM4.NewCBCEncrypter(key, iv)
	if err != nil {
		t.Fatalf("NewCBCEncrypter: %v", err)
	}
	ciphertext := make([]byte, len(padded))
	enc.CryptBlocks(ciphertext, padded)

	dec, err := polluxSM4.NewCBCDecrypter(key, iv)
	if err != nil {
		t.Fatalf("NewCBCDecrypter: %v", err)
	}
	decrypted := make([]byte, len(ciphertext))
	dec.CryptBlocks(decrypted, ciphertext)

	unpadded, err := polluxSM4.PKCS7Unpad(decrypted, 16)
	if err != nil {
		t.Fatalf("PKCS7Unpad: %v", err)
	}
	if !bytes.Equal(unpadded, plaintext) {
		t.Error("CBC roundtrip mismatch")
	}
}

// ========== CTR 流模式 ==========

func TestBlackBox_SM4_CTR_RoundTrip(t *testing.T) {
	key, _ := polluxSM4.GenerateKey()
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	plaintext := []byte("SM4-CTR mode streaming test")

	stream, err := polluxSM4.NewCTR(key, iv)
	if err != nil {
		t.Fatalf("NewCTR: %v", err)
	}
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	stream2, _ := polluxSM4.NewCTR(key, iv)
	decrypted := make([]byte, len(ciphertext))
	stream2.XORKeyStream(decrypted, ciphertext)

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("CTR roundtrip mismatch")
	}
}

// ========== CFB 流模式 ==========

func TestBlackBox_SM4_CFB_RoundTrip(t *testing.T) {
	key, _ := polluxSM4.GenerateKey()
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	plaintext := []byte("SM4-CFB mode streaming test")

	enc, err := polluxSM4.NewCFBEncrypter(key, iv) //nolint:staticcheck
	if err != nil {
		t.Fatalf("NewCFBEncrypter: %v", err)
	}
	ciphertext := make([]byte, len(plaintext))
	enc.XORKeyStream(ciphertext, plaintext)

	dec, err := polluxSM4.NewCFBDecrypter(key, iv) //nolint:staticcheck
	if err != nil {
		t.Fatalf("NewCFBDecrypter: %v", err)
	}
	decrypted := make([]byte, len(ciphertext))
	dec.XORKeyStream(decrypted, ciphertext)

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("CFB roundtrip mismatch")
	}
}

// ========== KDF ==========

func TestBlackBox_SM4_KDF(t *testing.T) {
	masterKey, _ := polluxSM4.GenerateKey()
	derived, err := polluxSM4.DeriveKey(masterKey, []byte("label"), []byte("context"), 32)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if len(derived) != 32 {
		t.Errorf("derived key length: got %d, want 32", len(derived))
	}
}

func TestBlackBox_SM4_KDF_Deterministic(t *testing.T) {
	key, _ := polluxSM4.GenerateKey()
	d1, _ := polluxSM4.DeriveKey(key, []byte("lbl"), []byte("ctx"), 16)
	d2, _ := polluxSM4.DeriveKey(key, []byte("lbl"), []byte("ctx"), 16)

	if !bytes.Equal(d1, d2) {
		t.Error("DeriveKey should be deterministic")
	}
}

func TestBlackBox_SM4_KDF_DifferentLabels(t *testing.T) {
	key, _ := polluxSM4.GenerateKey()
	d1, _ := polluxSM4.DeriveKey(key, []byte("label-A"), []byte("ctx"), 16)
	d2, _ := polluxSM4.DeriveKey(key, []byte("label-B"), []byte("ctx"), 16)

	if bytes.Equal(d1, d2) {
		t.Error("different labels should produce different keys")
	}
}

func TestBlackBox_SM4_KDF_ErrorCases(t *testing.T) {
	key, _ := polluxSM4.GenerateKey()

	_, err := polluxSM4.DeriveKey(key, nil, nil, 0)
	if err == nil {
		t.Error("should reject zero length")
	}
	_, err = polluxSM4.DeriveKey(key, nil, nil, -1)
	if err == nil {
		t.Error("should reject negative length")
	}
}

// ========== PKCS7 ==========

func TestBlackBox_SM4_PKCS7(t *testing.T) {
	data := []byte("1234567890123456") // 16 bytes = exact block
	padded, err := polluxSM4.PKCS7Pad(data, 16)
	if err != nil {
		t.Fatalf("PKCS7Pad: %v", err)
	}
	if len(padded) != 32 {
		t.Errorf("padded length: got %d, want 32 (added full block)", len(padded))
	}

	unpadded, err := polluxSM4.PKCS7Unpad(padded, 16)
	if err != nil {
		t.Fatalf("PKCS7Unpad: %v", err)
	}
	if !bytes.Equal(unpadded, data) {
		t.Error("PKCS7 roundtrip mismatch")
	}
}

func TestBlackBox_SM4_PKCS7_PartialBlock(t *testing.T) {
	data := []byte("12345") // 5 bytes, need 11 bytes padding
	padded, err := polluxSM4.PKCS7Pad(data, 16)
	if err != nil {
		t.Fatalf("PKCS7Pad: %v", err)
	}
	if len(padded) != 16 {
		t.Errorf("padded length: got %d, want 16", len(padded))
	}

	unpadded, err := polluxSM4.PKCS7Unpad(padded, 16)
	if err != nil {
		t.Fatalf("PKCS7Unpad: %v", err)
	}
	if !bytes.Equal(unpadded, data) {
		t.Error("PKCS7 partial block roundtrip mismatch")
	}
}

// ========== GenerateIV ==========

func TestBlackBox_SM4_GenerateIV(t *testing.T) {
	iv, err := polluxSM4.GenerateIV()
	if err != nil {
		t.Fatalf("GenerateIV: %v", err)
	}
	if len(iv) != 16 {
		t.Errorf("IV length: got %d, want 16", len(iv))
	}
}

func TestBlackBox_SM4_GenerateIV_Unique(t *testing.T) {
	iv1, _ := polluxSM4.GenerateIV()
	iv2, _ := polluxSM4.GenerateIV()
	if bytes.Equal(iv1, iv2) {
		t.Error("two IVs should be different")
	}
}

// ========== cipher.Block 接口 ==========

func TestBlackBox_SM4_NewCipher(t *testing.T) {
	key, _ := polluxSM4.GenerateKey()
	block, err := polluxSM4.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	var _ cipher.Block = block

	if block.BlockSize() != 16 {
		t.Errorf("block size: got %d, want 16", block.BlockSize())
	}
}

func TestBlackBox_SM4_NewCipher_InvalidKey(t *testing.T) {
	_, err := polluxSM4.NewCipher([]byte{1, 2, 3})
	if err == nil {
		t.Error("should reject invalid key size")
	}
}

// ========== GCM ==========

func TestBlackBox_SM4_GCM(t *testing.T) {
	key, _ := polluxSM4.GenerateKey()
	aead, err := polluxSM4.NewGCM(key)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}

	var _ cipher.AEAD = aead

	plaintext := []byte("SM4-GCM AEAD test")
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)

	ct := aead.Seal(nil, nonce, plaintext, nil)
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("GCM Open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Error("GCM roundtrip mismatch")
	}
}

// ========== ECB 模式 ==========

func TestBlackBox_SM4_ECB_RoundTrip(t *testing.T) {
	key, _ := polluxSM4.GenerateKey()
	plaintext := []byte("SM4-ECB mode test!!") // 18 bytes

	ct, err := polluxSM4.Encrypt(key, plaintext, polluxSM4.ModeECB, nil)
	if err != nil {
		t.Fatalf("ECB Encrypt: %v", err)
	}
	if len(ct)%16 != 0 {
		t.Errorf("ECB ciphertext not block-aligned: %d", len(ct))
	}

	dec, err := polluxSM4.Decrypt(key, ct, polluxSM4.ModeECB, nil)
	if err != nil {
		t.Fatalf("ECB Decrypt: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Error("ECB roundtrip mismatch")
	}
}

// ========== 高级 Encrypt/Decrypt API ==========

func TestBlackBox_SM4_EncryptDecrypt_CBC(t *testing.T) {
	key, _ := polluxSM4.GenerateKey()
	iv, _ := polluxSM4.GenerateIV()
	plaintext := []byte("high-level CBC test")

	ct, err := polluxSM4.Encrypt(key, plaintext, polluxSM4.ModeCBC, iv)
	if err != nil {
		t.Fatalf("Encrypt CBC: %v", err)
	}
	dec, err := polluxSM4.Decrypt(key, ct, polluxSM4.ModeCBC, iv)
	if err != nil {
		t.Fatalf("Decrypt CBC: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Error("high-level CBC roundtrip mismatch")
	}
}

func TestBlackBox_SM4_EncryptDecrypt_CTR(t *testing.T) {
	key, _ := polluxSM4.GenerateKey()
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	plaintext := []byte("high-level CTR test")

	ct, err := polluxSM4.Encrypt(key, plaintext, polluxSM4.ModeCTR, iv)
	if err != nil {
		t.Fatalf("Encrypt CTR: %v", err)
	}
	dec, err := polluxSM4.Decrypt(key, ct, polluxSM4.ModeCTR, iv)
	if err != nil {
		t.Fatalf("Decrypt CTR: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Error("high-level CTR roundtrip mismatch")
	}
}

func TestBlackBox_SM4_EncryptDecrypt_CFB(t *testing.T) {
	key, _ := polluxSM4.GenerateKey()
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	plaintext := []byte("high-level CFB test")

	ct, err := polluxSM4.Encrypt(key, plaintext, polluxSM4.ModeCFB, iv)
	if err != nil {
		t.Fatalf("Encrypt CFB: %v", err)
	}
	dec, err := polluxSM4.Decrypt(key, ct, polluxSM4.ModeCFB, iv)
	if err != nil {
		t.Fatalf("Decrypt CFB: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Error("high-level CFB roundtrip mismatch")
	}
}

func TestBlackBox_SM4_Encrypt_UnsupportedMode(t *testing.T) {
	key, _ := polluxSM4.GenerateKey()
	_, err := polluxSM4.Encrypt(key, []byte("test"), "FAKE", nil)
	if err == nil {
		t.Error("should reject unsupported mode")
	}
}
