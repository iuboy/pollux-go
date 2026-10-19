package sm4_test

import (
	"bytes"
	"testing"

	"github.com/iuboy/pollux-go/sm4"
)

// gcm_oneshot_test.go covers the one-shot GCM convenience functions in
// gcm.go that are NOT already covered by gcm_combined_test.go:
// SealRandomNonce, OpenWithNonce, GenerateNonce, ZeroNonce.
//
// Key-consumption contract: SealRandomNonce/OpenWithNonce defer ZeroKey on
// the caller's key slice, mutating it to all zeros before return. Each test
// passes a fresh copy so the original key survives for the decrypt side.

func TestSealRandomNonceOpenWithNonceRoundTrip(t *testing.T) {
	key, err := sm4.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	plaintext := []byte("pollux-go sm4-gcm oneshot roundtrip")
	aad := []byte("associated-data")

	// SealRandomNonce consumes the key — pass a copy.
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	sealed, err := sm4.SealRandomNonce(keyCopy, plaintext, aad)
	if err != nil {
		t.Fatalf("SealRandomNonce: %v", err)
	}
	// Verify the key copy was zeroed (consumed).
	for i, b := range keyCopy {
		if b != 0 {
			t.Errorf("SealRandomNonce did not zero key[%d] = %#x", i, b)
		}
	}
	// Nonce must be 12 bytes and ciphertext must include the 16-byte GCM tag.
	if len(sealed.Nonce) != sm4.GCMNonceSize {
		t.Errorf("nonce len = %d, want %d", len(sealed.Nonce), sm4.GCMNonceSize)
	}
	if len(sealed.Ciphertext) != len(plaintext)+16 {
		t.Errorf("ciphertext len = %d, want %d", len(sealed.Ciphertext), len(plaintext)+16)
	}

	// OpenWithNonce also consumes its key — pass the pristine original.
	keyCopy2 := make([]byte, len(key))
	copy(keyCopy2, key)
	pt, err := sm4.OpenWithNonce(keyCopy2, sealed, aad)
	if err != nil {
		t.Fatalf("OpenWithNonce: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("round-trip mismatch:\ngot  %x\nwant %x", pt, plaintext)
	}
}

func TestOpenWithNonceRejectsWrongAAD(t *testing.T) {
	key, _ := sm4.GenerateKey()
	plaintext := []byte("tamper-test")

	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	sealed, err := sm4.SealRandomNonce(keyCopy, plaintext, []byte("aad-correct"))
	if err != nil {
		t.Fatalf("SealRandomNonce: %v", err)
	}

	keyCopy2 := make([]byte, len(key))
	copy(keyCopy2, key)
	if _, err := sm4.OpenWithNonce(keyCopy2, sealed, []byte("aad-wrong")); err == nil {
		t.Error("OpenWithNonce should reject wrong AAD")
	}
}

func TestOpenWithNonceRejectsBadNonceLength(t *testing.T) {
	key, _ := sm4.GenerateKey()
	// A Sealed value with a wrong-length nonce must be rejected before Open.
	bad := sm4.Sealed{Nonce: make([]byte, 8), Ciphertext: make([]byte, 32)}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	_, err := sm4.OpenWithNonce(keyCopy, bad, nil)
	if err == nil {
		t.Error("OpenWithNonce should reject non-12-byte nonce")
	}
}

func TestSealRandomNonceRejectsBadKey(t *testing.T) {
	// A short key must error (and still be zeroed by the deferred ZeroKey).
	shortKey := []byte{1, 2, 3}
	if _, err := sm4.SealRandomNonce(shortKey, []byte("x"), nil); err == nil {
		t.Error("SealRandomNonce should reject short key")
	}
}

func TestGenerateNonce(t *testing.T) {
	n, err := sm4.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	if len(n) != sm4.GCMNonceSize {
		t.Errorf("nonce len = %d, want %d", len(n), sm4.GCMNonceSize)
	}
	// Two nonces must differ (random).
	n2, _ := sm4.GenerateNonce()
	if bytes.Equal(n, n2) {
		t.Error("GenerateNonce produced identical nonces")
	}
}

func TestZeroNonce(t *testing.T) {
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	sm4.ZeroNonce(nonce)
	for i, b := range nonce {
		if b != 0 {
			t.Errorf("ZeroNonce: byte %d = %#x, want 0", i, b)
		}
	}
}
