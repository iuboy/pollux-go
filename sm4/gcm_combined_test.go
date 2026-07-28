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
func TestSealCombined_OpenCombined_RoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey err = %v", err)
	}
	defer ZeroKey(key)

	plaintext := []byte("pollux-go sm4 combined + aad")
	aad := []byte("entity-id")

	combined, err := SealCombined(key, plaintext, aad)
	if err != nil {
		t.Fatalf("SealCombined err = %v", err)
	}
	// Layout: nonce(12) || ct(=len(pt)+16 tag)
	if len(combined) != GCMNonceSize+len(plaintext)+16 {
		t.Errorf("combined len = %d, want %d", len(combined), GCMNonceSize+len(plaintext)+16)
	}

	pt, err := OpenCombined(key, combined, aad)
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
	combined, _ := SealCombined(key, []byte("payload"), []byte("aad-a"))
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
	key, _ := GenerateKey()
	defer ZeroKey(key)
	a, _ := SealCombined(key, []byte("x"), nil)
	b, _ := SealCombined(key, []byte("x"), nil)
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
	key, _ := GenerateKey()
	defer ZeroKey(key)
	plaintext := []byte("layout check")

	combined, _ := SealCombined(key, plaintext, nil)
	encrypted, _ := Encrypt(key, plaintext, ModeGCM, nil)

	if len(combined) != len(encrypted) {
		t.Errorf("SealCombined len %d != Encrypt(ModeGCM) len %d", len(combined), len(encrypted))
	}
	// Sanity: keep strings imported meaningful (no-op assertion).
	if !strings.HasPrefix(string(plaintext), "layout") {
		t.Error("unexpected plaintext")
	}
}
