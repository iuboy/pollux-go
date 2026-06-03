package sm3_test

import (
	"bytes"
	"testing"

	"github.com/ycq/pollux/sm3"
)

// ---------------------------------------------------------------------------
// HKDFExtract
// ---------------------------------------------------------------------------

func TestHKDFExtractOutputLength(t *testing.T) {
	prk := sm3.HKDFExtract([]byte("salt"), []byte("ikm"))
	if len(prk) != sm3.Size {
		t.Fatalf("HKDFExtract returned %d bytes, want %d", len(prk), sm3.Size)
	}
}

func TestHKDFExtractDeterministic(t *testing.T) {
	salt := []byte("fixed-salt")
	ikm := []byte("fixed-input-keying-material")
	prk1 := sm3.HKDFExtract(salt, ikm)
	prk2 := sm3.HKDFExtract(salt, ikm)
	if !bytes.Equal(prk1, prk2) {
		t.Fatal("HKDFExtract is not deterministic: two calls with same inputs produced different results")
	}
}

func TestHKDFExtractEmptySaltUsesDefault(t *testing.T) {
	ikm := []byte("some-input-material")
	prkNil := sm3.HKDFExtract(nil, ikm)
	prkEmpty := sm3.HKDFExtract([]byte{}, ikm)
	if !bytes.Equal(prkNil, prkEmpty) {
		t.Fatal("HKDFExtract(nil) and HKDFExtract([]byte{}) should produce the same result")
	}
	if len(prkNil) != sm3.Size {
		t.Fatalf("empty-salt PRK length = %d, want %d", len(prkNil), sm3.Size)
	}
}

func TestHKDFExtractDifferentSalts(t *testing.T) {
	ikm := []byte("same-ikm")
	prk1 := sm3.HKDFExtract([]byte("salt-alpha-for-test"), ikm)
	prk2 := sm3.HKDFExtract([]byte("salt-beta-for-test"), ikm)
	if bytes.Equal(prk1, prk2) {
		t.Fatal("different salts should produce different PRKs")
	}
}

func TestHKDFExtractDifferentIKM(t *testing.T) {
	salt := []byte("same-salt")
	prk1 := sm3.HKDFExtract(salt, []byte("ikm-alpha"))
	prk2 := sm3.HKDFExtract(salt, []byte("ikm-beta"))
	if bytes.Equal(prk1, prk2) {
		t.Fatal("different IKMs should produce different PRKs")
	}
}

func TestHKDFExtractKnownAnswer(t *testing.T) {
	salt := []byte("extract-salt")
	ikm := []byte("extract-ikm")

	expected := []byte{
		0x45, 0xbd, 0x28, 0x01, 0x41, 0xc6, 0xe7, 0x51,
		0xee, 0x2a, 0x2f, 0xb9, 0xcf, 0xa5, 0x5a, 0xf4,
		0x30, 0x74, 0xc2, 0xfd, 0x8f, 0x74, 0xb1, 0xd0,
		0x3c, 0x3f, 0x78, 0xf9, 0x18, 0x25, 0x06, 0x0d,
	}

	got := sm3.HKDFExtract(salt, ikm)
	if !bytes.Equal(got, expected) {
		t.Fatalf("extract known-answer mismatch:\ngot  %x\nwant %x", got, expected)
	}
}

// ---------------------------------------------------------------------------
// HKDFExpand
// ---------------------------------------------------------------------------

func TestHKDFExpandOutputLength(t *testing.T) {
	prk := make([]byte, sm3.Size)
	for i := range prk {
		prk[i] = byte(i)
	}

	for _, l := range []int{1, 16, 31, 32, 33, 48, 64, 100} {
		out, err := sm3.HKDFExpand(prk, []byte("info"), l)
		if err != nil {
			t.Fatalf("HKDFExpand length=%d: unexpected error: %v", l, err)
		}
		if len(out) != l {
			t.Errorf("HKDFExpand(length=%d) returned %d bytes, want %d", l, len(out), l)
		}
	}
}

func TestHKDFExpandDeterministic(t *testing.T) {
	prk := make([]byte, sm3.Size)
	for i := range prk {
		prk[i] = byte(i)
	}
	info := []byte("context-info")
	out1, err := sm3.HKDFExpand(prk, info, 48)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := sm3.HKDFExpand(prk, info, 48)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out1, out2) {
		t.Fatal("HKDFExpand is not deterministic")
	}
}

func TestHKDFExpandZeroLength(t *testing.T) {
	prk := make([]byte, sm3.Size)
	_, err := sm3.HKDFExpand(prk, nil, 0)
	if err == nil {
		t.Fatal("expected error for zero length, got nil")
	}
}

func TestHKDFExpandTooLarge(t *testing.T) {
	prk := make([]byte, sm3.Size)
	_, err := sm3.HKDFExpand(prk, nil, 255*sm3.Size+1)
	if err == nil {
		t.Fatal("expected error for length exceeding 255*HashSize, got nil")
	}
}

func TestHKDFExpandMaxLength(t *testing.T) {
	prk := make([]byte, sm3.Size)
	out, err := sm3.HKDFExpand(prk, nil, 255*sm3.Size)
	if err != nil {
		t.Fatalf("unexpected error for max length: %v", err)
	}
	if len(out) != 255*sm3.Size {
		t.Fatalf("max length output = %d, want %d", len(out), 255*sm3.Size)
	}
}

func TestHKDFExpandEmptyInfo(t *testing.T) {
	prk := make([]byte, sm3.Size)
	for i := range prk {
		prk[i] = byte(i)
	}
	out1, err := sm3.HKDFExpand(prk, nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := sm3.HKDFExpand(prk, []byte{}, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out1, out2) {
		t.Fatal("HKDFExpand with nil info and empty info should produce the same result")
	}
}

func TestHKDFExpandKnownAnswer(t *testing.T) {
	prk := make([]byte, sm3.Size)
	for i := range prk {
		prk[i] = byte(i)
	}
	info := []byte("expand-info")

	expected := []byte{
		0x34, 0x4f, 0xa7, 0xfc, 0x8c, 0x4a, 0xee, 0x01,
		0x59, 0x87, 0xe6, 0xdd, 0x38, 0xad, 0x82, 0xaa,
		0x32, 0x9d, 0x83, 0xca, 0x4f, 0x7f, 0x83, 0x5a,
		0x9b, 0x62, 0xac, 0x1f, 0x55, 0x8c, 0x16, 0xce,
		0x17, 0x23, 0x40, 0x32, 0xcd, 0x6f, 0xd0, 0x4c,
		0x1d, 0x8e, 0x60, 0x0f, 0x0c, 0x1b, 0x77, 0x04,
	}

	got, err := sm3.HKDFExpand(prk, info, 48)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("expand known-answer mismatch:\ngot  %x\nwant %x", got, expected)
	}
}

// ---------------------------------------------------------------------------
// HKDF (full Extract + Expand)
// ---------------------------------------------------------------------------

func TestHKDFRoundTrip(t *testing.T) {
	salt := []byte("test-salt")
	ikm := []byte("input-keying-material")
	info := []byte("context")

	full, err := sm3.HKDF(salt, ikm, info, 48)
	if err != nil {
		t.Fatal(err)
	}

	prk := sm3.HKDFExtract(salt, ikm)
	manual, err := sm3.HKDFExpand(prk, info, 48)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(full, manual) {
		t.Fatal("HKDF(salt,ikm,info,L) != HKDFExpand(HKDFExtract(salt,ikm), info, L)")
	}
}

func TestHKDFDeterministic(t *testing.T) {
	salt := []byte("salt")
	ikm := []byte("ikm")
	info := []byte("info")

	out1, err := sm3.HKDF(salt, ikm, info, 32)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := sm3.HKDF(salt, ikm, info, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out1, out2) {
		t.Fatal("HKDF is not deterministic")
	}
}

func TestHKDFZeroLength(t *testing.T) {
	_, err := sm3.HKDF([]byte("salt"), []byte("ikm"), nil, 0)
	if err == nil {
		t.Fatal("expected error for zero length, got nil")
	}
}

func TestHKDFNegativeLength(t *testing.T) {
	_, err := sm3.HKDF([]byte("salt"), []byte("ikm"), nil, -1)
	if err == nil {
		t.Fatal("expected error for negative length, got nil")
	}
}

func TestHKDFDifferentSalts(t *testing.T) {
	ikm := []byte("same-ikm")

	salt1 := []byte("salt-alpha-for-test")
	salt2 := []byte("salt-beta-for-test")

	prk1 := sm3.HKDFExtract(salt1, ikm)
	prk2 := sm3.HKDFExtract(salt2, ikm)
	if bytes.Equal(prk1, prk2) {
		t.Fatal("HKDFExtract should produce different PRKs for different salts")
	}

	info := []byte("same-info")
	out1, _ := sm3.HKDF(salt1, ikm, info, 32)
	out2, _ := sm3.HKDF(salt2, ikm, info, 32)

	if bytes.Equal(out1, out2) {
		t.Fatal("different salts should produce different HKDF outputs")
	}
}

func TestHKDFDifferentInfo(t *testing.T) {
	salt := []byte("same-salt")
	ikm := []byte("same-ikm")

	out1, _ := sm3.HKDF(salt, ikm, []byte("info-alpha"), 32)
	out2, _ := sm3.HKDF(salt, ikm, []byte("info-beta"), 32)
	if bytes.Equal(out1, out2) {
		t.Fatal("different info should produce different outputs")
	}
}

func TestHKDFEmptySalt(t *testing.T) {
	ikm := []byte("input-material")
	info := []byte("info")

	outNil, _ := sm3.HKDF(nil, ikm, info, 32)
	outEmpty, _ := sm3.HKDF([]byte{}, ikm, info, 32)
	if !bytes.Equal(outNil, outEmpty) {
		t.Fatal("HKDF with nil salt and empty salt should produce the same result")
	}

	prkNil := sm3.HKDFExtract(nil, ikm)
	prkExplicit := sm3.HKDFExtract([]byte("salt"), ikm)
	if bytes.Equal(prkNil, prkExplicit) {
		t.Fatal("empty salt and non-empty salt should produce different PRKs in Extract")
	}
}

func TestHKDFVariousLengths(t *testing.T) {
	salt := []byte("salt")
	ikm := []byte("ikm")
	info := []byte("info")

	for _, length := range []int{16, 32, 48, 64} {
		out, err := sm3.HKDF(salt, ikm, info, length)
		if err != nil {
			t.Fatalf("HKDF length=%d: unexpected error: %v", length, err)
		}
		if len(out) != length {
			t.Errorf("HKDF length=%d: got %d bytes", length, len(out))
		}
	}
}

func TestHKDFSubHashLength(t *testing.T) {
	salt := []byte("salt")
	ikm := []byte("ikm")
	info := []byte("info")

	out16, err := sm3.HKDF(salt, ikm, info, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(out16) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(out16))
	}

	out32, err := sm3.HKDF(salt, ikm, info, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out16, out32[:16]) {
		t.Fatal("shorter output must be prefix of longer output from same inputs")
	}
}

func TestHKDFMultiBlockLength(t *testing.T) {
	salt := []byte("salt")
	ikm := []byte("ikm")
	info := []byte("info")

	out48, err := sm3.HKDF(salt, ikm, info, 48)
	if err != nil {
		t.Fatal(err)
	}
	if len(out48) != 48 {
		t.Fatalf("expected 48 bytes, got %d", len(out48))
	}

	out32, _ := sm3.HKDF(salt, ikm, info, 32)
	if !bytes.Equal(out32, out48[:32]) {
		t.Fatal("first 32 bytes of 48-byte output must match 32-byte output")
	}
}

func TestHKDFConsistency(t *testing.T) {
	salt := []byte("consistency-salt")
	ikm := []byte("consistency-ikm")
	info := []byte("consistency-info")

	var prev []byte
	for i := 0; i < 10; i++ {
		out, err := sm3.HKDF(salt, ikm, info, 64)
		if err != nil {
			t.Fatal(err)
		}
		if prev != nil && !bytes.Equal(prev, out) {
			t.Fatalf("iteration %d: output differs from previous", i)
		}
		prev = out
	}
}

func TestHKDFKnownAnswer(t *testing.T) {
	salt := []byte("known-answer-salt")
	ikm := []byte("known-answer-ikm")
	info := []byte("known-answer-info")

	expected := []byte{
		0xe1, 0x7e, 0xb3, 0x86, 0x4f, 0x3f, 0x8c, 0x67,
		0x34, 0x8c, 0x7b, 0x20, 0xfb, 0xcc, 0x9b, 0x9d,
		0x5c, 0xb9, 0x15, 0xa2, 0x39, 0x44, 0xd9, 0xdd,
		0xb7, 0xa0, 0xf5, 0x3e, 0xd9, 0xf7, 0x7b, 0xea,
	}

	got, err := sm3.HKDF(salt, ikm, info, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("known-answer mismatch:\ngot  %x\nwant %x", got, expected)
	}
}

func TestHKDFKnownAnswerEmptySalt(t *testing.T) {
	ikm := []byte("ikm-without-salt")
	info := []byte("some-context")

	expected := []byte{
		0x6a, 0x23, 0x0c, 0x70, 0x64, 0x8a, 0x52, 0x94,
		0x82, 0x54, 0x8c, 0x5a, 0xe4, 0x8e, 0x28, 0x5a,
		0x92, 0xe5, 0xd9, 0x27, 0x8b, 0x94, 0x77, 0x1d,
		0xdd, 0xde, 0xc4, 0x0e, 0xa0, 0x91, 0xe1, 0x1a,
	}

	got, err := sm3.HKDF(nil, ikm, info, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("known-answer (empty salt) mismatch:\ngot  %x\nwant %x", got, expected)
	}
}

func TestHKDFKnownAnswer48Byte(t *testing.T) {
	salt := []byte("salt-48")
	ikm := []byte("ikm-48")
	info := []byte("info-48")

	expected := []byte{
		0xb7, 0x97, 0x87, 0x2b, 0x4c, 0x6c, 0xc0, 0x0d,
		0x66, 0x7c, 0x8f, 0x32, 0xd1, 0x6f, 0x94, 0x08,
		0x04, 0x4c, 0x56, 0x24, 0x40, 0xa7, 0x7c, 0x68,
		0x53, 0x7c, 0x68, 0xc3, 0xe7, 0xbc, 0xa8, 0xec,
		0xc8, 0x78, 0xca, 0x4f, 0xa9, 0x82, 0x13, 0x0b,
		0x9d, 0x4c, 0xd9, 0x5e, 0x4a, 0xa6, 0x15, 0xd5,
	}

	got, err := sm3.HKDF(salt, ikm, info, 48)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("known-answer (48-byte) mismatch:\ngot  %x\nwant %x", got, expected)
	}
}

func TestHKDFEmptyInfo(t *testing.T) {
	salt := []byte("salt")
	ikm := []byte("ikm")

	outWithInfo, _ := sm3.HKDF(salt, ikm, []byte("info"), 32)
	outNoInfo, _ := sm3.HKDF(salt, ikm, nil, 32)
	outEmptyInfo, _ := sm3.HKDF(salt, ikm, []byte{}, 32)

	if !bytes.Equal(outNoInfo, outEmptyInfo) {
		t.Fatal("nil info and empty info should produce the same result")
	}
	if bytes.Equal(outWithInfo, outNoInfo) {
		t.Fatal("output with info should differ from output without info")
	}
}

func TestHKDFEmptyIKM(t *testing.T) {
	salt := []byte("salt")
	out, err := sm3.HKDF(salt, []byte{}, []byte("info"), 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(out))
	}
}

func TestHKDFVeryLargeLength(t *testing.T) {
	salt := []byte("salt")
	ikm := []byte("ikm")
	out, err := sm3.HKDF(salt, ikm, nil, 255*sm3.Size)
	if err != nil {
		t.Fatalf("unexpected error for max output length: %v", err)
	}
	if len(out) != 255*sm3.Size {
		t.Fatalf("expected %d bytes, got %d", 255*sm3.Size, len(out))
	}
}

func TestHKDFOverMaxLength(t *testing.T) {
	_, err := sm3.HKDF([]byte("salt"), []byte("ikm"), nil, 255*sm3.Size+1)
	if err == nil {
		t.Fatal("expected error for output length > 255*HashSize")
	}
}

func TestHKDFLengthOne(t *testing.T) {
	out, err := sm3.HKDF([]byte("salt"), []byte("ikm"), []byte("info"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 byte, got %d", len(out))
	}
}

func TestHKDFOutputPrefixProperty(t *testing.T) {
	salt := []byte("prefix-salt")
	ikm := []byte("prefix-ikm")
	info := []byte("prefix-info")

	out64, _ := sm3.HKDF(salt, ikm, info, 64)
	out16, _ := sm3.HKDF(salt, ikm, info, 16)
	out32, _ := sm3.HKDF(salt, ikm, info, 32)
	out48, _ := sm3.HKDF(salt, ikm, info, 48)

	if !bytes.Equal(out16, out64[:16]) {
		t.Error("16-byte output is not a prefix of 64-byte output")
	}
	if !bytes.Equal(out32, out64[:32]) {
		t.Error("32-byte output is not a prefix of 64-byte output")
	}
	if !bytes.Equal(out48, out64[:48]) {
		t.Error("48-byte output is not a prefix of 64-byte output")
	}
}

func TestHKDFExpandPrefixProperty(t *testing.T) {
	prk := make([]byte, sm3.Size)
	for i := range prk {
		prk[i] = byte(i)
	}
	info := []byte("prefix-test")

	out64, _ := sm3.HKDFExpand(prk, info, 64)
	out16, _ := sm3.HKDFExpand(prk, info, 16)
	out32, _ := sm3.HKDFExpand(prk, info, 32)

	if !bytes.Equal(out16, out64[:16]) {
		t.Error("16-byte expand output is not a prefix of 64-byte output")
	}
	if !bytes.Equal(out32, out64[:32]) {
		t.Error("32-byte expand output is not a prefix of 64-byte output")
	}
}
