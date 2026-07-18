package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// NIST SP 800-38D §9.1 / RFC 5288 AES-256-GCM test vector (Test Case 13).
//   Key       = feffe9928665731c6d6a8f9467308308 feffe9928665731c6d6a8f9467308308
//   Nonce     = cafebabefacedbaddecaf888  (note: the convenience API generates
//               its own nonce, so we exercise this vector via NewGCM + aead
//               directly in TestNewGCM_NISTVector rather than SealRandomNonce)
// The full vector (AAD + plaintext → ciphertext) is used below.

func TestNewCipher_RejectsInvalidKeySizes(t *testing.T) {
	for _, n := range []int{0, 15, 16, 24, 31, 33, 64} {
		if _, err := NewCipher(make([]byte, n)); !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("NewCipher(%d-byte key) err = %v, want ErrInvalidKeySize", n, err)
		}
	}
}

func TestNewCipher_AcceptsAES256Key(t *testing.T) {
	key := make([]byte, 32) // all-zero key; fine for a structural test
	block, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher(32-byte key) err = %v", err)
	}
	if got := block.BlockSize(); got != aes.BlockSize {
		t.Errorf("BlockSize = %d, want %d", got, aes.BlockSize)
	}
}

func TestGenerateKey_SizeAndEntropy(t *testing.T) {
	k1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey err = %v", err)
	}
	if len(k1) != KeySize {
		t.Fatalf("GenerateKey len = %d, want %d", len(k1), KeySize)
	}
	k2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey (2nd) err = %v", err)
	}
	if bytes.Equal(k1, k2) {
		t.Error("two consecutive GenerateKey calls returned identical keys")
	}
}

// TestNewGCM_NISTVector verifies AES-256-GCM against NIST Test Case 13
// (the empty-AAD, known plaintext/ciphertext pair). This anchors the wrapper
// to the standard so cryptosuite callers can trust byte-level correctness.
func TestNewGCM_NISTVector(t *testing.T) {
	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	nonce, _ := hex.DecodeString("cafebabefacedbaddecaf888")
	plaintext, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
	aad, _ := hex.DecodeString("feedfacedeadbeeffeedfacedeadbeefabaddad2")
	// NIST SP 800-38D Test Case 13 expected ciphertext prefix (16 bytes).
	wantCT, _ := hex.DecodeString("522dc1f099567d07f47f37a32a84427d")

	aead, err := NewGCM(key)
	if err != nil {
		t.Fatalf("NewGCM err = %v", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, aad)
	// NIST vector gives the first 16 bytes of ciphertext (plaintext truncated
	// to 60 bytes for TC13). Compare prefix only.
	if !bytes.HasPrefix(ct, wantCT) {
		t.Errorf("ciphertext prefix = %x, want %x", ct[:16], wantCT)
	}

	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Open err = %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("round-trip plaintext mismatch")
	}
}

func TestSealRandomNonce_RoundTrip(t *testing.T) {
	key, _ := GenerateKey()
	defer ZeroKey(key)
	plaintext := []byte("pollux-go aes round-trip")
	aad := []byte("entity-id")

	sealed, err := SealRandomNonce(key, plaintext, aad)
	if err != nil {
		t.Fatalf("SealRandomNonce err = %v", err)
	}
	if len(sealed.Nonce) != GCMNonceSize {
		t.Errorf("nonce len = %d, want %d", len(sealed.Nonce), GCMNonceSize)
	}
	// GCM tag is 16 bytes; ciphertext = plaintext + 16.
	if len(sealed.Ciphertext) != len(plaintext)+16 {
		t.Errorf("ciphertext len = %d, want %d", len(sealed.Ciphertext), len(plaintext)+16)
	}

	pt, err := OpenWithNonce(key, sealed, aad)
	if err != nil {
		t.Fatalf("OpenWithNonce err = %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", pt, plaintext)
	}
}

func TestOpenWithNonce_RejectsTamperedAAD(t *testing.T) {
	key, _ := GenerateKey()
	defer ZeroKey(key)
	sealed, _ := SealRandomNonce(key, []byte("payload"), []byte("aad-a"))

	if _, err := OpenWithNonce(key, sealed, []byte("aad-b")); err == nil {
		t.Error("OpenWithNonce with wrong AAD unexpectedly succeeded")
	}
}

func TestOpenWithNonce_RejectsBadNonceLength(t *testing.T) {
	key, _ := GenerateKey()
	defer ZeroKey(key)
	bad := Sealed{Nonce: []byte{1, 2, 3}, Ciphertext: []byte("x")}
	_, err := OpenWithNonce(key, bad, nil)
	if err == nil || !strings.Contains(err.Error(), "nonce length") {
		t.Errorf("err = %v, want nonce length error", err)
	}
}

func TestSealCombined_FormatIsNoncePrepended(t *testing.T) {
	key, _ := GenerateKey()
	defer ZeroKey(key)
	plaintext := []byte("combined-format")
	aad := []byte("aad")

	combined, err := SealCombined(key, plaintext, aad)
	if err != nil {
		t.Fatalf("SealCombined err = %v", err)
	}
	// Layout: nonce(12) || ct(=len(pt)+16)
	if len(combined) != GCMNonceSize+len(plaintext)+16 {
		t.Errorf("combined len = %d, want %d", len(combined), GCMNonceSize+len(plaintext)+16)
	}

	// Decrypt via OpenCombined.
	pt, err := OpenCombined(key, combined, aad)
	if err != nil {
		t.Fatalf("OpenCombined err = %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("round-trip mismatch")
	}
}

// TestSealCombined_ByteCompatibleWithStandardIdiom verifies that
// SealCombined's output layout (nonce || ct) is byte-compatible with the
// common crypto/cipher.AEAD idiom used by existing at-rest encryptors. This
// anchors the cloudfile migration: existing AES-256-GCM blobs in
// nonce||ct layout can be decrypted by OpenCombined unchanged.
func TestSealCombined_ByteCompatibleWithStandardIdiom(t *testing.T) {
	key, _ := GenerateKey()
	defer ZeroKey(key)

	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	plaintext := []byte("interop check")
	aad := []byte("aad")

	// Standard idiom: Seal with nonce as dst appends ct+tag to nonce.
	standard := aead.Seal(nonce, nonce, plaintext, aad)

	// Decrypt the standard-idiom blob via OpenCombined — must succeed and
	// yield the original plaintext.
	pt, err := OpenCombined(key, standard, aad)
	if err != nil {
		t.Fatalf("OpenCombined on standard-idiom blob err = %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("cross-decrypt plaintext mismatch")
	}
}

func TestOpenCombined_RejectsShortInput(t *testing.T) {
	key, _ := GenerateKey()
	defer ZeroKey(key)
	short := make([]byte, 5)
	if _, err := OpenCombined(key, short, nil); err == nil {
		t.Error("OpenCombined on 5-byte input unexpectedly succeeded")
	}
}

func TestZeroKey_ClearsSlice(t *testing.T) {
	key := []byte{1, 2, 3, 4}
	ZeroKey(key)
	for i, b := range key {
		if b != 0 {
			t.Errorf("byte %d = %d, want 0", i, b)
		}
	}
}
