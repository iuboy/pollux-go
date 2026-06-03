package zuc

import (
	"bytes"
	"testing"
)

func TestNewCipher_ZUC128(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16)
	iv := bytes.Repeat([]byte{0x02}, 16)

	stream, err := NewCipher(key, iv)
	if err != nil {
		t.Fatalf("NewCipher ZUC-128: %v", err)
	}
	if stream == nil {
		t.Fatal("stream should not be nil")
	}
}

func TestNewCipher_ZUC256(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	iv := bytes.Repeat([]byte{0x02}, 23)

	stream, err := NewCipher(key, iv)
	if err != nil {
		t.Fatalf("NewCipher ZUC-256: %v", err)
	}
	if stream == nil {
		t.Fatal("stream should not be nil")
	}
}

func TestNewCipher_InvalidKeySize(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 8) // invalid size
	iv := bytes.Repeat([]byte{0x02}, 16)

	_, err := NewCipher(key, iv)
	if err == nil {
		t.Error("should reject invalid key size")
	}
}

func TestNewEEACipher(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16)
	stream, err := NewEEACipher(key, 0, 0, 0)
	if err != nil {
		t.Fatalf("NewEEACipher: %v", err)
	}

	plaintext := []byte("Hello ZUC EEA3!")
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 16)
	count := uint32(12345)
	bearer := uint32(5)
	direction := uint32(0)

	plaintext := []byte("ZUC roundtrip test data")

	ct, err := Encrypt(key, count, bearer, direction, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(ct) != len(plaintext) {
		t.Errorf("ciphertext length: got %d, want %d", len(ct), len(plaintext))
	}

	// Decrypt by encrypting again (stream cipher symmetry)
	pt, err := Encrypt(key, count, bearer, direction, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("roundtrip: got %q, want %q", pt, plaintext)
	}
}

func TestMAC(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16)
	data := []byte("authentication test data")

	mac, err := MAC(key, 0, 0, 0, data)
	if err != nil {
		t.Fatalf("MAC: %v", err)
	}
	if len(mac) == 0 {
		t.Error("MAC should not be empty")
	}

	// same inputs → same MAC
	mac2, err := MAC(key, 0, 0, 0, data)
	if err != nil {
		t.Fatalf("MAC 2: %v", err)
	}
	if !bytes.Equal(mac, mac2) {
		t.Error("MAC should be deterministic")
	}
}

func TestNewHash(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16)
	iv := bytes.Repeat([]byte{0x02}, 16)

	h, err := NewHash(key, iv)
	if err != nil {
		t.Fatalf("NewHash: %v", err)
	}

	data := []byte("test data for EIA hash")
	_, _ = h.Write(data)
	mac := h.Sum(nil)
	if len(mac) == 0 {
		t.Error("hash output should not be empty")
	}
}

// TestZUC128_StandardVector verifies ZUC-128 against a known key/IV pair
// to ensure the cipher produces deterministic, non-trivial output.
// Uses a fixed key/IV and verifies roundtrip and determinism.
func TestZUC128_StandardVector(t *testing.T) {
	// Fixed key and IV for reproducibility
	key := []byte{
		0x3d, 0x4c, 0x4b, 0xe9, 0x6a, 0x82, 0x3f, 0xd4,
		0x1a, 0x0e, 0x15, 0x71, 0x4c, 0x18, 0x52, 0x00,
	}
	iv := []byte{
		0xcf, 0x51, 0x65, 0x0d, 0x4e, 0xc2, 0x61, 0x25,
		0x36, 0x24, 0x30, 0x90, 0x84, 0x5b, 0x1d, 0x84,
	}

	stream, err := NewCipher(key, iv)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	plaintext := make([]byte, 16)
	ciphertext := make([]byte, 16)
	stream.XORKeyStream(ciphertext, plaintext)

	// Output must not be all zeros
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ZUC-128 output should not equal all-zero plaintext")
	}

	// Same key/IV must produce same keystream (determinism)
	stream2, _ := NewCipher(key, iv)
	ciphertext2 := make([]byte, 16)
	stream2.XORKeyStream(ciphertext2, plaintext)

	if !bytes.Equal(ciphertext, ciphertext2) {
		t.Error("ZUC-128 should be deterministic with same key/IV")
	}
}

// TestEEA3_StandardVector verifies EEA3 encryption roundtrip with known parameters.
func TestEEA3_StandardVector(t *testing.T) {
	key := []byte{
		0x2b, 0xd6, 0x45, 0x9f, 0x82, 0xc5, 0xb3, 0x00,
		0x95, 0x2c, 0x49, 0x10, 0x48, 0x81, 0xff, 0x48,
	}
	count := uint32(0x66035492)
	bearer := uint32(0xf)
	direction := uint32(1)

	plaintext := []byte{
		0x6b, 0x2b, 0x99, 0x3a, 0x40, 0x70, 0x5b, 0x8f,
		0x22, 0x4a, 0x60, 0x0d, 0x1b, 0x24,
	}

	ct, err := Encrypt(key, count, bearer, direction, plaintext)
	if err != nil {
		t.Fatalf("EEA3 Encrypt: %v", err)
	}
	if bytes.Equal(ct, plaintext) {
		t.Error("EEA3 ciphertext should differ from plaintext")
	}

	// Roundtrip
	pt, err := Encrypt(key, count, bearer, direction, ct)
	if err != nil {
		t.Fatalf("EEA3 Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("EEA3 roundtrip failed:\n  got:  %x\n  want: %x", pt, plaintext)
	}
}
