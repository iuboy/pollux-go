package test

import (
	"bytes"
	"testing"

	polluxSM3 "github.com/iuboy/pollux-go/sm3"
)

func TestBlackBox_SM3_Sum_EmptyInput(t *testing.T) {
	h := polluxSM3.Sum(nil) //nolint:staticcheck
	if len(h) != 32 {
		t.Errorf("SM3 hash length: got %d, want 32", len(h))
	}
}

func TestBlackBox_SM3_Sum_Deterministic(t *testing.T) {
	h1 := polluxSM3.Sum([]byte("test"))
	h2 := polluxSM3.Sum([]byte("test"))
	if !bytes.Equal(h1[:], h2[:]) {
		t.Error("SM3 should be deterministic")
	}
}

func TestBlackBox_SM3_Sum_DifferentInput(t *testing.T) {
	h1 := polluxSM3.Sum([]byte("input A"))
	h2 := polluxSM3.Sum([]byte("input B"))
	if bytes.Equal(h1[:], h2[:]) {
		t.Error("different inputs should produce different hashes")
	}
}

func TestBlackBox_SM3_New_HashInterface(t *testing.T) {
	h := polluxSM3.New()
	if h.Size() != 32 {
		t.Errorf("Size: got %d, want 32", h.Size())
	}
	if h.BlockSize() <= 0 {
		t.Error("BlockSize should be positive")
	}
}

func TestBlackBox_SM3_New_StreamingMatchesSum(t *testing.T) {
	data := []byte("streaming vs sum comparison")

	h := polluxSM3.New()
	h.Write(data)
	streamed := h.Sum(nil)

	summed := polluxSM3.Sum(data)
	if !bytes.Equal(streamed, summed[:]) {
		t.Error("streaming hash should match Sum")
	}
}

func TestBlackBox_SM3_New_Reset(t *testing.T) {
	h := polluxSM3.New()
	h.Write([]byte("first"))
	mac1 := h.Sum(nil)

	h.Reset()
	h.Write([]byte("first"))
	mac2 := h.Sum(nil)

	if !bytes.Equal(mac1, mac2) {
		t.Error("Reset + same write should produce same result")
	}
}

func TestBlackBox_SM3_KDF_RoundTrip(t *testing.T) {
	z := []byte("shared-secret-for-kdf")
	out, err := polluxSM3.KDF(z, 32)
	if err != nil {
		t.Fatalf("KDF: %v", err)
	}
	if len(out) != 32 {
		t.Errorf("KDF length: got %d, want 32", len(out))
	}
}

func TestBlackBox_SM3_KDF_ZeroLength(t *testing.T) {
	_, err := polluxSM3.KDF([]byte("z"), 0)
	if err == nil {
		t.Error("KDF(0) should return error")
	}
}

func TestBlackBox_SM3_KDF_NilZ(t *testing.T) {
	_, err := polluxSM3.KDF(nil, 16)
	if err == nil {
		t.Error("KDF(nil) should return error")
	}
}

func TestBlackBox_SM3_KDF_Deterministic(t *testing.T) {
	z := []byte("kdf-determinism-test")
	d1, _ := polluxSM3.KDF(z, 32)
	d2, _ := polluxSM3.KDF(z, 32)
	if !bytes.Equal(d1, d2) {
		t.Error("KDF should be deterministic")
	}
}

func TestBlackBox_SM3_HKDF_RoundTrip(t *testing.T) {
	salt := []byte("salt-value")
	ikm := []byte("input-keying-material")
	info := []byte("info")

	out, err := polluxSM3.HKDF(salt, ikm, info, 32)
	if err != nil {
		t.Fatalf("HKDF: %v", err)
	}
	if len(out) != 32 {
		t.Errorf("HKDF length: got %d, want 32", len(out))
	}
}
