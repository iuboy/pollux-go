package tls13gm

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// randomSM4Key generates a random 16-byte SM4 key for tests.
func randomSM4Key(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate SM4 key: %v", err)
	}
	return key
}

func TestConstants(t *testing.T) {
	if TLS_SM4_GCM_SM3 != 0x00C6 {
		t.Errorf("TLS_SM4_GCM_SM3: got 0x%04X, want 0x00C6", TLS_SM4_GCM_SM3)
	}
	if TLS_SM4_CCM_SM3 != 0x00C7 {
		t.Errorf("TLS_SM4_CCM_SM3: got 0x%04X, want 0x00C7", TLS_SM4_CCM_SM3)
	}
}

func TestSuiteName(t *testing.T) {
	tests := []struct {
		id   uint16
		want string
	}{
		{TLS_SM4_GCM_SM3, "TLS_SM4_GCM_SM3"},
		{TLS_SM4_CCM_SM3, "TLS_SM4_CCM_SM3"},
		{0xFFFF, "unknown"},
	}
	for _, tt := range tests {
		got := SuiteName(tt.id)
		if got != tt.want {
			t.Errorf("SuiteName(0x%04X): got %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestHKDFExpandLabel(t *testing.T) {
	secret := make([]byte, 32)
	label := "c hs traffic"
	context := make([]byte, 32)
	result, err := HKDFExpandLabel(secret, label, context, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 32 {
		t.Errorf("result length: got %d, want 32", len(result))
	}
}

func TestHKDFExpandLabel_Deterministic(t *testing.T) {
	secret := make([]byte, 32)
	r1, _ := HKDFExpandLabel(secret, "key", nil, 16)
	r2, _ := HKDFExpandLabel(secret, "key", nil, 16)
	if !bytes.Equal(r1, r2) {
		t.Error("HKDF should be deterministic")
	}
}

func TestDeriveSecret(t *testing.T) {
	secret := make([]byte, 32)
	result, err := DeriveSecret(secret, "derived", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 32 {
		t.Errorf("result length: got %d, want 32", len(result))
	}
}

func TestAEAD_RoundTrip(t *testing.T) {
	key := randomSM4Key(t)
	fixedNonce := make([]byte, 12)

	aead, err := NewAEAD(key, fixedNonce)
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("hello tls13gm")
	aad := []byte("tls13 record")

	ct, err := aead.Seal(0, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := aead.Open(0, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Error("roundtrip mismatch")
	}
}

func TestAEAD_DifferentSeqNum(t *testing.T) {
	key := randomSM4Key(t)
	fixedNonce := make([]byte, 12)

	aead, err := NewAEAD(key, fixedNonce)
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("same plaintext")

	ct0, _ := aead.Seal(0, pt, nil)
	ct1, _ := aead.Seal(1, pt, nil)
	if bytes.Equal(ct0, ct1) {
		t.Error("different seq numbers should produce different ciphertext")
	}

	got, err := aead.Open(1, ct1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Error("roundtrip mismatch for seq 1")
	}
}

func TestAEAD_WrongSeqNum(t *testing.T) {
	key := randomSM4Key(t)
	fixedNonce := make([]byte, 12)

	aead, err := NewAEAD(key, fixedNonce)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := aead.Seal(0, []byte("secret"), nil)
	_, err = aead.Open(1, ct, nil)
	if err == nil {
		t.Error("wrong seq number should fail")
	}
}

func TestAEAD_TamperedCiphertext(t *testing.T) {
	key := randomSM4Key(t)
	fixedNonce := make([]byte, 12)

	aead, err := NewAEAD(key, fixedNonce)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := aead.Seal(0, []byte("secret"), nil)
	ct[0] ^= 0xff
	_, err = aead.Open(0, ct, nil)
	if err == nil {
		t.Error("tampered ciphertext should fail")
	}
}
