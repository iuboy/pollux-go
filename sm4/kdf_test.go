package sm4_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/iuboy/pollux-go/sm4"
)

// TestKDFBasicConsistency verifies that deriving the same key twice
// with identical inputs produces identical output.
func TestKDFBasicConsistency(t *testing.T) {
	masterKey := makeTestKey(t)
	label := []byte("test-label")
	context := []byte("test-context")

	k1, err := sm4.DeriveKey(masterKey, label, context, 32)
	if err != nil {
		t.Fatalf("first DeriveKey: %v", err)
	}
	k2, err := sm4.DeriveKey(masterKey, label, context, 32)
	if err != nil {
		t.Fatalf("second DeriveKey: %v", err)
	}

	if !equalBytes(k1, k2) {
		t.Errorf("identical inputs produced different keys:\n  %s\n  %s",
			hex.EncodeToString(k1), hex.EncodeToString(k2))
	}
}

// TestKDFDeriveDifferentLengths derives keys of 16, 32, and 48 bytes
// and verifies that each produced key has the correct length.
func TestKDFDeriveDifferentLengths(t *testing.T) {
	masterKey := makeTestKey(t)
	label := []byte("test-label")
	context := []byte("test-context")

	for _, length := range []int{1, 8, 15, 16, 17, 31, 32, 48, 64, 80, 256} {
		key, err := sm4.DeriveKey(masterKey, label, context, length)
		if err != nil {
			t.Fatalf("DeriveKey(length=%d): %v", length, err)
		}
		if len(key) != length {
			t.Errorf("length=%d: got %d bytes, want %d", length, len(key), length)
		}
	}
}

// TestKDFDifferentLabels verifies that changing the label produces
// a different derived key. We test with multiple length outputs since
// the KDF includes length_in_bits in the round input.
func TestKDFDifferentLabels(t *testing.T) {
	masterKey := makeTestKey(t)
	context := []byte("shared-context")

	pairs := []struct{ a, b string }{
		{"encryption-key", "mac-key"},
		{"short", "a-much-longer-label-name"},
		{"alpha", "beta"},
	}
	for _, p := range pairs {
		k1, err := sm4.DeriveKey(masterKey, []byte(p.a), context, 16)
		if err != nil {
			t.Fatal(err)
		}
		k2, err := sm4.DeriveKey(masterKey, []byte(p.b), context, 16)
		if err != nil {
			t.Fatal(err)
		}
		if equalBytes(k1, k2) {
			t.Errorf("labels %q and %q produced identical keys: %s",
				p.a, p.b, hex.EncodeToString(k1))
		}
	}
}

// TestKDFDifferentContexts verifies that changing the context produces
// a different derived key.
func TestKDFDifferentContexts(t *testing.T) {
	masterKey := makeTestKey(t)
	label := []byte("shared-label")

	k1, err := sm4.DeriveKey(masterKey, label, []byte("context-1"), 16)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := sm4.DeriveKey(masterKey, label, []byte("context-2"), 16)
	if err != nil {
		t.Fatal(err)
	}

	if equalBytes(k1, k2) {
		t.Errorf("different contexts produced identical keys: %s", hex.EncodeToString(k1))
	}
}

// TestKDFErrorCases validates error handling for invalid inputs.
func TestKDFErrorCases(t *testing.T) {
	validKey := makeTestKey(t)
	label := []byte("label")
	context := []byte("context")

	tests := []struct {
		name      string
		masterKey []byte
		length    int
	}{
		{"nil master key", nil, 16},
		{"short master key", []byte{1, 2, 3}, 16},
		{"zero length", validKey, 0},
		{"negative length", validKey, -1},
		{"negative length large", validKey, -100},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sm4.DeriveKey(tc.masterKey, label, context, tc.length)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// TestKDFMultiRound verifies multi-round derivation where the requested
// length exceeds a single SM4 block (16 bytes). We request 80 bytes (5 rounds)
// and check that the output has the correct size and is non-trivial.
func TestKDFMultiRound(t *testing.T) {
	masterKey := makeTestKey(t)
	label := []byte("multi-round")
	context := []byte("context")

	// 80 bytes requires 5 rounds (5 * 16 = 80, exact fit).
	key, err := sm4.DeriveKey(masterKey, label, context, 80)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 80 {
		t.Fatalf("got %d bytes, want 80", len(key))
	}

	// The result should not be all zeros.
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("derived key is all zeros")
	}

	// Consistency: derive again and compare.
	key2, err := sm4.DeriveKey(masterKey, label, context, 80)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(key, key2) {
		t.Error("multi-round derivation is not deterministic")
	}
}

// TestKDFPartialBlock verifies derivation of a non-block-aligned length.
// Requesting 17 bytes should produce exactly 17 bytes.
func TestKDFPartialBlock(t *testing.T) {
	masterKey := makeTestKey(t)
	label := []byte("partial")
	context := []byte("ctx")

	k17, err := sm4.DeriveKey(masterKey, label, context, 17)
	if err != nil {
		t.Fatal(err)
	}
	if len(k17) != 17 {
		t.Fatalf("got %d bytes, want 17", len(k17))
	}

	// Consistency: derive again and verify.
	k17b, _ := sm4.DeriveKey(masterKey, label, context, 17)
	if !equalBytes(k17, k17b) {
		t.Error("partial-block derivation is not deterministic")
	}
}

// TestKDFSingleByte verifies the minimum non-trivial derivation.
func TestKDFSingleByte(t *testing.T) {
	masterKey := makeTestKey(t)

	k, err := sm4.DeriveKey(masterKey, []byte("l"), []byte("c"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != 1 {
		t.Fatalf("got %d bytes, want 1", len(k))
	}
}

// TestKDFKnownAnswer is a regression test with hardcoded expected values.
// These vectors were computed by running DeriveKey once with fixed inputs
// and recording the hex output. Any change that alters these values is
// either a bug or a breaking API change.
//
// masterKey = "0123456789abcdef" (ASCII, 16 bytes)
// label     = "test-label"
// context   = "test-context"
func TestKDFKnownAnswer(t *testing.T) {
	masterKey := []byte("0123456789abcdef")
	label := []byte("test-label")
	context := []byte("test-context")

	vectors := []struct {
		length int
		hex    string
	}{
		// Single-round: 16 bytes (1 block)
		{16, "f47c9426c8cfbc17c5dd40034cb89fb5"},
		// Two-round: 32 bytes (2 blocks)
		{32, "aad6ef28074097e6f5afb477a104c89126e7fcf7978af300d4bb9b3cd52aff7f"},
		// Three-round: 48 bytes (3 blocks)
		{48, "2e001a8d44fcf7e48eb5d57b862d5e2ec89a8ad8a658d84f7630c22d3d44b8ecb822fcc9397049ed73facc79aaa3c9ad"},
		// Single byte
		{1, "46"},
		// 15 bytes (partial block)
		{15, "940d2885e3b31f656a10f0f7ce7f33"},
		// 17 bytes (1 full block + 1 byte)
		{17, "3a73e0ff56e889eed9aadb3938f8a9d89f"},
		// 64 bytes (4 rounds)
		{64, "c56b7bed1bf1b113ca5a77c13d5959dd7d3597c4ccbeaa4b16b229e5f350479e05b5154ebbe15cb7dadcfe7682224b7c8c3b7562633f25955e8db5fb3487331e"},
		// 80 bytes (5 rounds)
		{80, "5e7f515b6e65df98a034cabc131429e59f60318b89c57ca71acc97293c9b2a3d29809d948d990a0c3fd2f9446f26b5c932325e87b850df5607ceff0742801d464eb60ddcccc142e86198c36b25e458ef"},
	}

	for _, v := range vectors {
		t.Run(fmt.Sprintf("len_%d", v.length), func(t *testing.T) {
			got, err := sm4.DeriveKey(masterKey, label, context, v.length)
			if err != nil {
				t.Fatalf("DeriveKey(%d): %v", v.length, err)
			}
			gotHex := hex.EncodeToString(got)
			if gotHex != v.hex {
				t.Errorf("length=%d:\n  got  %s\n  want %s", v.length, gotHex, v.hex)
			}
		})
	}
}

// TestKDFKnownAnswerDifferentInputs uses a different label/context pair
// for an independent regression vector.
func TestKDFKnownAnswerDifferentInputs(t *testing.T) {
	masterKey := []byte("0123456789abcdef")
	label := []byte("my-app")
	context := []byte("session-key")

	// 32-byte key with the alternate label/context.
	want := "90ec8b5b5b7d291d7599b639f12ec7b9849c1fa5eff25dca1e77dc0a69eb00b3"
	got, err := sm4.DeriveKey(masterKey, label, context, 32)
	if err != nil {
		t.Fatal(err)
	}
	gotHex := hex.EncodeToString(got)
	if gotHex != want {
		// If this fails, print the actual value so it can be updated.
		t.Fatalf("got %s, want %s", gotHex, want)
	}
}

// TestKDFEmptyLabelAndContext verifies that empty label and context are
// handled correctly (the separator byte 0x00 is still included in the
// round input).
func TestKDFEmptyLabelAndContext(t *testing.T) {
	masterKey := makeTestKey(t)

	key, err := sm4.DeriveKey(masterKey, []byte{}, []byte{}, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 16 {
		t.Fatalf("got %d bytes, want 16", len(key))
	}

	// Empty label+context should differ from non-empty.
	keyNonEmpty, _ := sm4.DeriveKey(masterKey, []byte("a"), []byte("b"), 16)
	if equalBytes(key, keyNonEmpty) {
		t.Error("empty and non-empty label/context produced same key")
	}
}

// TestKDFEmptyLabelOnly verifies empty label with non-empty context,
// and that nil and empty-slice labels produce identical results.
func TestKDFEmptyLabelOnly(t *testing.T) {
	masterKey := makeTestKey(t)
	context := []byte("some-context")

	k1, err := sm4.DeriveKey(masterKey, []byte{}, context, 32)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := sm4.DeriveKey(masterKey, nil, context, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(k1, k2) {
		t.Error("empty byte slice and nil label should produce same key")
	}
}

// TestKDFEmptyContextOnly verifies empty context with non-empty label,
// and that nil and empty-slice contexts produce identical results.
func TestKDFEmptyContextOnly(t *testing.T) {
	masterKey := makeTestKey(t)
	label := []byte("some-label")

	k1, err := sm4.DeriveKey(masterKey, label, []byte{}, 32)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := sm4.DeriveKey(masterKey, label, nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(k1, k2) {
		t.Error("empty byte slice and nil context should produce same key")
	}
}

// TestKDFLargeOutput verifies derivation of a large key (256 bytes = 16 rounds).
func TestKDFLargeOutput(t *testing.T) {
	masterKey := makeTestKey(t)

	key, err := sm4.DeriveKey(masterKey, []byte("big"), []byte("out"), 256)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 256 {
		t.Fatalf("got %d bytes, want 256", len(key))
	}

	// Not all zeros.
	for _, b := range key {
		if b != 0 {
			return
		}
	}
	t.Error("256-byte derived key is all zeros")
}

// TestKDFDifferentMasterKeys verifies that different master keys
// produce different derived keys.
func TestKDFDifferentMasterKeys(t *testing.T) {
	label := []byte("label")
	context := []byte("context")

	k1, err := sm4.DeriveKey([]byte("0123456789abcdef"), label, context, 16)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := sm4.DeriveKey([]byte("fedcba9876543210"), label, context, 16)
	if err != nil {
		t.Fatal(err)
	}

	if equalBytes(k1, k2) {
		t.Error("different master keys produced identical derived keys")
	}
}

// TestKDFLengthAffectsOutput verifies that requesting different lengths
// from the same inputs produces different outputs (because the length-in-bits
// field is part of the round input per NIST SP 800-108).
func TestKDFLengthAffectsOutput(t *testing.T) {
	masterKey := makeTestKey(t)
	label := []byte("test-label")
	context := []byte("test-context")

	k16, _ := sm4.DeriveKey(masterKey, label, context, 16)
	k32, _ := sm4.DeriveKey(masterKey, label, context, 32)

	// The first block of k32 should differ from k16 because the L field
	// (length in bits) is different: 128 vs 256.
	if equalBytes(k16, k32[:16]) {
		t.Errorf("length field did not affect round output\n  len=16: %s\n  len=32[:16]: %s",
			hex.EncodeToString(k16), hex.EncodeToString(k32[:16]))
	}
}

// --- helpers ---

// makeTestKey returns a fixed 16-byte key for deterministic tests.
func makeTestKey(t *testing.T) []byte {
	t.Helper()
	return []byte("0123456789abcdef")
}

// equalBytes compares two byte slices.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
