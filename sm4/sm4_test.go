package sm4_test

import (
	"crypto/cipher"
	"testing"

	"github.com/ycq/pollux/sm4"
)

func TestNewCipherReturnsCipherBlock(t *testing.T) {
	key, err := sm4.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	var block cipher.Block
	block, err = sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	if block.BlockSize() != sm4.BlockSize {
		t.Errorf("BlockSize() = %d, want %d", block.BlockSize(), sm4.BlockSize)
	}
}

func TestNewCipherInvalidKey(t *testing.T) {
	_, err := sm4.NewCipher([]byte("short"))
	if err == nil {
		t.Error("expected error for short key")
	}
}

func TestGCMViaStdlib(t *testing.T) {
	key, err := sm4.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	var aead cipher.AEAD
	aead, err = cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello sm4-gcm world")
	sealed := aead.Seal(nil, make([]byte, 12), plaintext, nil)
	opened, err := aead.Open(nil, make([]byte, 12), sealed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != string(plaintext) {
		t.Errorf("decrypted mismatch")
	}
}

func TestCBCViaStdlib(t *testing.T) {
	key, err := sm4.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := make([]byte, sm4.BlockSize*2)
	copy(plaintext, "hello sm4-cbc")

	iv := make([]byte, sm4.BlockSize)
	cbcEnc := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	cbcEnc.CryptBlocks(ciphertext, plaintext)

	cbcDec := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	cbcDec.CryptBlocks(decrypted, ciphertext)

	if string(decrypted) != string(plaintext) {
		t.Errorf("CBC decrypted mismatch")
	}
}

func TestGenerateKeySize(t *testing.T) {
	key, err := sm4.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != sm4.KeySize {
		t.Errorf("GenerateKey returned %d bytes, want %d", len(key), sm4.KeySize)
	}
}
