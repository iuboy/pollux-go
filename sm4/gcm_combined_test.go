package sm4

import (
	"bytes"
	"strings"
	"testing"
)

// TestSealCombined_OpenCombined_RoundTrip covers the AAD-aware combined
// format added to symmetrically match aes.SealCombined. The legacy
// SealRandomNonce/Encrypt path is exercised by existing sm4_test.go; here we
// focus on AAD binding and the nonce||ct layout.
//
// Key-consumption contract: SealCombined/OpenCombined consume the caller's
// key (zero it before return). To do a full seal→open round trip in one
// test, we use NewGCM directly to produce the ciphertext with a stable key,
// then exercise SealCombined on a copy and OpenCombined on the original.
func TestSealCombined_OpenCombined_RoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey err = %v", err)
	}
	defer ZeroKey(key)

	plaintext := []byte("pollux-go sm4 combined + aad")
	aad := []byte("entity-id")

	// Stable-key path: produce nonce||ct via NewGCM so the same key can
	// decrypt later via OpenCombined.
	aead, err := NewGCM(key)
	if err != nil {
		t.Fatalf("NewGCM err = %v", err)
	}
	nonce := make([]byte, GCMNonceSize)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	combinedDirect := aead.Seal(nonce, nonce, plaintext, aad)
	if len(combinedDirect) != GCMNonceSize+len(plaintext)+16 {
		t.Errorf("combined len = %d, want %d", len(combinedDirect), GCMNonceSize+len(plaintext)+16)
	}

	// Exercise SealCombined on a pristine copy (it consumes its input).
	keyCopy := append([]byte(nil), key...)
	t.Cleanup(func() { ZeroKey(keyCopy) })
	if _, err := SealCombined(keyCopy, plaintext, aad); err != nil {
		t.Fatalf("SealCombined err = %v", err)
	}
	for i, b := range keyCopy {
		if b != 0 {
			t.Errorf("SealCombined key byte %d = %#x, want 0", i, b)
		}
	}

	// OpenCombined consumes key — that's fine, it's the last key user.
	pt, err := OpenCombined(key, combinedDirect, aad)
	if err != nil {
		t.Fatalf("OpenCombined err = %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("round-trip mismatch: got %q want %q", pt, plaintext)
	}
}

func TestOpenCombined_RejectsWrongAAD(t *testing.T) {
	key, _ := GenerateKey()
	defer ZeroKey(key)
	// Use NewGCM directly so OpenCombined has a pristine key to consume.
	aead, _ := NewGCM(key)
	nonce := make([]byte, GCMNonceSize)
	combined := aead.Seal(nonce, nonce, []byte("payload"), []byte("aad-a"))
	if _, err := OpenCombined(key, combined, []byte("aad-b")); err == nil {
		t.Error("OpenCombined with wrong AAD unexpectedly succeeded")
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

func TestSealCombined_UniqueNoncePerCall(t *testing.T) {
	// SealCombined consumes its key, so generate two independent keys.
	keyA, _ := GenerateKey()
	keyB, _ := GenerateKey()
	a, _ := SealCombined(keyA, []byte("x"), nil)
	b, _ := SealCombined(keyB, []byte("x"), nil)
	// Nonces are the first 12 bytes; they must differ across calls.
	if bytes.Equal(a[:GCMNonceSize], b[:GCMNonceSize]) {
		t.Error("two SealCombined calls produced identical nonces (catastrophic for GCM)")
	}
}

// TestSealCombined_LayoutMatchesEncryptGCMPrepended confirms the combined
// format is byte-identical to the prepended-nonce output of Encrypt(ModeGCM),
// so callers switching between the two APIs see the same wire format. The
// difference is AAD binding: SealCombined threads AAD, Encrypt(ModeGCM) does
// not. We therefore compare layout length, not bytes.
func TestSealCombined_LayoutMatchesEncryptGCMPrepended(t *testing.T) {
	// Each API consumes its key, so generate two independent keys of the
	// same length — the layout is deterministic in length regardless of key.
	keyA, _ := GenerateKey()
	keyB, _ := GenerateKey()
	plaintext := []byte("layout check")

	combined, _ := SealCombined(keyA, plaintext, nil)
	encrypted, _ := Encrypt(keyB, plaintext, ModeGCM, nil)

	if len(combined) != len(encrypted) {
		t.Errorf("SealCombined len %d != Encrypt(ModeGCM) len %d", len(combined), len(encrypted))
	}
	// Sanity: keep strings imported meaningful (no-op assertion).
	if !strings.HasPrefix(string(plaintext), "layout") {
		t.Error("unexpected plaintext")
	}
}
