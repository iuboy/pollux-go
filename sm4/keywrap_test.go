package sm4

import (
	"bytes"
	"testing"
)

func TestKeyWrapRoundTrip16ByteKey(t *testing.T) {
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	plaintextKey := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}

	wrapped, err := KeyWrap(kek, plaintextKey)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}
	if len(wrapped) != len(plaintextKey)+8 {
		t.Errorf("wrapped length = %d, want %d", len(wrapped), len(plaintextKey)+8)
	}

	unwrapped, err := KeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("KeyUnwrap failed: %v", err)
	}
	if !bytes.Equal(unwrapped, plaintextKey) {
		t.Errorf("unwrapped key mismatch\ngot:  %x\nwant: %x", unwrapped, plaintextKey)
	}
}

func TestKeyWrapRoundTrip32ByteKey(t *testing.T) {
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	plaintextKey := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
		0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
	}

	wrapped, err := KeyWrap(kek, plaintextKey)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}
	if len(wrapped) != len(plaintextKey)+8 {
		t.Errorf("wrapped length = %d, want %d", len(wrapped), len(plaintextKey)+8)
	}

	unwrapped, err := KeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("KeyUnwrap failed: %v", err)
	}
	if !bytes.Equal(unwrapped, plaintextKey) {
		t.Errorf("unwrapped key mismatch\ngot:  %x\nwant: %x", unwrapped, plaintextKey)
	}
}

func TestKeyWrapIntegrityTamperedCiphertext(t *testing.T) {
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	plaintextKey := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}

	wrapped, err := KeyWrap(kek, plaintextKey)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	// Tamper with the first byte of the wrapped ciphertext.
	wrapped[0] ^= 0xFF

	_, err = KeyUnwrap(kek, wrapped)
	if err == nil {
		t.Fatal("expected unwrap to fail with tampered ciphertext, but it succeeded")
	}
}

func TestKeyWrapWrongKEK(t *testing.T) {
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	wrongKEK := []byte{
		0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
		0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
	}
	plaintextKey := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}

	wrapped, err := KeyWrap(kek, plaintextKey)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	_, err = KeyUnwrap(wrongKEK, wrapped)
	if err == nil {
		t.Fatal("expected unwrap to fail with wrong KEK, but it succeeded")
	}
}

func TestKeyWrapEmptyPlaintext(t *testing.T) {
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}

	_, err := KeyWrap(kek, []byte{})
	if err == nil {
		t.Fatal("expected wrap of empty key to fail, but it succeeded")
	}
}

func TestKeyWrapPlaintextTooShort(t *testing.T) {
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	// 8 bytes is less than the required 16-byte minimum.
	shortKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	_, err := KeyWrap(kek, shortKey)
	if err == nil {
		t.Fatal("expected wrap of 8-byte key to fail, but it succeeded")
	}
}

func TestKeyWrapPlaintextNotMultipleOf8(t *testing.T) {
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	// 17 bytes: not a multiple of 8.
	oddKey := make([]byte, 17)
	for i := range oddKey {
		oddKey[i] = byte(i)
	}

	_, err := KeyWrap(kek, oddKey)
	if err == nil {
		t.Fatal("expected wrap of non-multiple-of-8 key to fail, but it succeeded")
	}
}

func TestKeyWrapInvalidKEKSize(t *testing.T) {
	// KEK too short (15 bytes).
	shortKEK := make([]byte, 15)
	plaintextKey := make([]byte, 16)

	_, err := KeyWrap(shortKEK, plaintextKey)
	if err == nil {
		t.Fatal("expected wrap with short KEK to fail, but it succeeded")
	}

	// KEK too long (32 bytes).
	longKEK := make([]byte, 32)
	_, err = KeyWrap(longKEK, plaintextKey)
	if err == nil {
		t.Fatal("expected wrap with long KEK to fail, but it succeeded")
	}

	// Unwrap with short KEK.
	ciphertext := make([]byte, 24)
	_, err = KeyUnwrap(shortKEK, ciphertext)
	if err == nil {
		t.Fatal("expected unwrap with short KEK to fail, but it succeeded")
	}
}

func TestKeyUnwrapCiphertextTooShort(t *testing.T) {
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	// 16 bytes: less than the required 24-byte minimum for ciphertext.
	shortCiphertext := make([]byte, 16)

	_, err := KeyUnwrap(kek, shortCiphertext)
	if err == nil {
		t.Fatal("expected unwrap of short ciphertext to fail, but it succeeded")
	}
}

func TestKeyUnwrapCiphertextNotMultipleOf8(t *testing.T) {
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	// 25 bytes: not a multiple of 8.
	oddCiphertext := make([]byte, 25)

	_, err := KeyUnwrap(kek, oddCiphertext)
	if err == nil {
		t.Fatal("expected unwrap of non-multiple-of-8 ciphertext to fail, but it succeeded")
	}
}

func TestKeyWrapRFC3394StyleVectors(t *testing.T) {
	// RFC 3394 Section 4.1/4.2 style test vectors adapted for SM4.
	// Since SM4 uses a different block cipher than AES, the intermediate
	// values differ, but we verify that wrap/unwrap round-trips correctly.
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	keyToWrap := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}

	wrapped, err := KeyWrap(kek, keyToWrap)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	// Wrapped output must be deterministic: wrapping the same inputs
	// must produce the same output every time.
	wrapped2, err := KeyWrap(kek, keyToWrap)
	if err != nil {
		t.Fatalf("second KeyWrap failed: %v", err)
	}
	if !bytes.Equal(wrapped, wrapped2) {
		t.Fatal("KeyWrap is not deterministic: two calls with same input produced different output")
	}

	unwrapped, err := KeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("KeyUnwrap failed: %v", err)
	}
	if !bytes.Equal(unwrapped, keyToWrap) {
		t.Errorf("round-trip mismatch\ngot:  %x\nwant: %x", unwrapped, keyToWrap)
	}
}

func TestKeyWrap32ByteKeyWith16ByteKEK(t *testing.T) {
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	// 32-byte key to wrap (e.g., an AES-256 or SM4 double-length key).
	plaintextKey := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}

	wrapped, err := KeyWrap(kek, plaintextKey)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	// 32 bytes plaintext + 8 bytes IV = 40 bytes ciphertext.
	if len(wrapped) != 40 {
		t.Errorf("wrapped length = %d, want 40", len(wrapped))
	}

	unwrapped, err := KeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("KeyUnwrap failed: %v", err)
	}
	if !bytes.Equal(unwrapped, plaintextKey) {
		t.Errorf("round-trip mismatch for 32-byte key\ngot:  %x\nwant: %x", unwrapped, plaintextKey)
	}
}

func TestKeyWrapTamperedMiddleBlock(t *testing.T) {
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	plaintextKey := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
		0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
	}

	wrapped, err := KeyWrap(kek, plaintextKey)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	// Tamper with the last byte of the wrapped output.
	wrapped[len(wrapped)-1] ^= 0x01

	_, err = KeyUnwrap(kek, wrapped)
	if err == nil {
		t.Fatal("expected unwrap to fail with tampered last byte, but it succeeded")
	}
}

func TestKeyWrapAllZeros(t *testing.T) {
	kek := make([]byte, 16)
	plaintextKey := make([]byte, 16)

	wrapped, err := KeyWrap(kek, plaintextKey)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	unwrapped, err := KeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("KeyUnwrap failed: %v", err)
	}
	if !bytes.Equal(unwrapped, plaintextKey) {
		t.Errorf("round-trip mismatch for zero key\ngot:  %x\nwant: %x", unwrapped, plaintextKey)
	}
}

func TestKeyWrapAllOnes(t *testing.T) {
	kek := make([]byte, 16)
	for i := range kek {
		kek[i] = 0xFF
	}
	plaintextKey := make([]byte, 16)
	for i := range plaintextKey {
		plaintextKey[i] = 0xFF
	}

	wrapped, err := KeyWrap(kek, plaintextKey)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	unwrapped, err := KeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("KeyUnwrap failed: %v", err)
	}
	if !bytes.Equal(unwrapped, plaintextKey) {
		t.Errorf("round-trip mismatch for 0xFF key\ngot:  %x\nwant: %x", unwrapped, plaintextKey)
	}
}

func TestKeyWrapMultipleSizes(t *testing.T) {
	kek := []byte{
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	}

	sizes := []int{16, 24, 32, 48, 64}
	for _, size := range sizes {
		plaintextKey := make([]byte, size)
		for i := range plaintextKey {
			plaintextKey[i] = byte(i)
		}

		wrapped, err := KeyWrap(kek, plaintextKey)
		if err != nil {
			t.Errorf("size %d: KeyWrap failed: %v", size, err)
			continue
		}
		if len(wrapped) != size+8 {
			t.Errorf("size %d: wrapped length = %d, want %d", size, len(wrapped), size+8)
		}

		unwrapped, err := KeyUnwrap(kek, wrapped)
		if err != nil {
			t.Errorf("size %d: KeyUnwrap failed: %v", size, err)
			continue
		}
		if !bytes.Equal(unwrapped, plaintextKey) {
			t.Errorf("size %d: round-trip mismatch", size)
		}
	}
}

func TestKeyWrapOutputOverwriteSafe(t *testing.T) {
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	plaintextKey := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}

	wrapped1, err := KeyWrap(kek, plaintextKey)
	if err != nil {
		t.Fatalf("first KeyWrap failed: %v", err)
	}

	// Modify the original plaintext to ensure wrap did not retain a reference.
	plaintextKey[0] ^= 0xFF

	wrapped2, err := KeyWrap(kek, plaintextKey)
	if err != nil {
		t.Fatalf("second KeyWrap failed: %v", err)
	}

	// The two wrapped outputs must differ because the plaintext differs.
	if bytes.Equal(wrapped1, wrapped2) {
		t.Error("wrapping different plaintexts produced the same output")
	}
}
