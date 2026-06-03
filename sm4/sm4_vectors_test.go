package sm4_test

import (
	"encoding/hex"
	"testing"

	"github.com/ycq/pollux/sm4"
)

// GM/T 0002-2012 标准测试向量

func TestStandardVector(t *testing.T) {
	// GM/T 0002-2012 Section 4, Example 1
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	wantCiphertext := "681edf34d206965e86b3e94f536e4246"

	block, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	dst := make([]byte, sm4.BlockSize)
	block.Encrypt(dst, plaintext)

	gotHex := hex.EncodeToString(dst)
	if gotHex != wantCiphertext {
		t.Errorf("Encrypt\ngot:  %s\nwant: %s", gotHex, wantCiphertext)
	}

	// Verify decrypt
	decrypted := make([]byte, sm4.BlockSize)
	block.Decrypt(decrypted, dst)
	if hex.EncodeToString(decrypted) != hex.EncodeToString(plaintext) {
		t.Errorf("Decrypt\ngot:  %x\nwant: %x", decrypted, plaintext)
	}
}

func TestIterationVector(t *testing.T) {
	// GM/T 0002-2012: 1,000,000 iterations starting from standard test vector
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	initial, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	wantAfter1M := "595298c7c6fd271f0402f804c33d3f66"

	block, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	data := make([]byte, sm4.BlockSize)
	copy(data, initial)

	for i := 0; i < 1000000; i++ {
		dst := make([]byte, sm4.BlockSize)
		block.Encrypt(dst, data)
		data = dst
	}

	gotHex := hex.EncodeToString(data)
	if gotHex != wantAfter1M {
		t.Errorf("1M iterations\ngot:  %s\nwant: %s", gotHex, wantAfter1M)
	}
}

func TestInvalidKeySize(t *testing.T) {
	_, err := sm4.NewCipher([]byte("short"))
	if err == nil {
		t.Error("expected error for short key")
	}

	_, err = sm4.NewCipher(make([]byte, 32))
	if err == nil {
		t.Error("expected error for 32-byte key")
	}

	_, err = sm4.NewCipher(make([]byte, 0))
	if err == nil {
		t.Error("expected error for empty key")
	}
}

func TestBlockSize(t *testing.T) {
	key, _ := sm4.GenerateKey()
	block, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	if block.BlockSize() != sm4.BlockSize {
		t.Errorf("BlockSize() = %d, want %d", block.BlockSize(), sm4.BlockSize)
	}
	if sm4.BlockSize != 16 {
		t.Errorf("BlockSize constant = %d, want 16", sm4.BlockSize)
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key, err := sm4.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	for _, size := range []int{0, 1, 8, 15, 16} {
		plaintext := make([]byte, sm4.BlockSize)
		for i := range plaintext {
			plaintext[i] = byte(i + size)
		}

		ciphertext := make([]byte, sm4.BlockSize)
		block.Encrypt(ciphertext, plaintext)

		decrypted := make([]byte, sm4.BlockSize)
		block.Decrypt(decrypted, ciphertext)

		if string(decrypted) != string(plaintext) {
			t.Errorf("roundtrip failed for size offset %d", size)
		}
	}
}
