package test

import (
	"bytes"
	"crypto/rand"
	"testing"

	polluxSM4GCM "github.com/ycq/pollux/sm4gcm"
	polluxTLS13GM "github.com/ycq/pollux/tls13gm"
)

func TestBlackBox_TLS13GM_CipherSuiteConstants(t *testing.T) {
	if polluxTLS13GM.TLS_SM4_GCM_SM3 != 0x00C6 {
		t.Errorf("TLS_SM4_GCM_SM3: got 0x%04x, want 0x00C6", polluxTLS13GM.TLS_SM4_GCM_SM3)
	}
	if polluxTLS13GM.TLS_SM4_CCM_SM3 != 0x00C7 {
		t.Errorf("TLS_SM4_CCM_SM3: got 0x%04x, want 0x00C7", polluxTLS13GM.TLS_SM4_CCM_SM3)
	}
}

func TestBlackBox_TLS13GM_SignatureSchemeConstants(t *testing.T) {
	if polluxTLS13GM.SM2SigSM3 != 0x0708 {
		t.Errorf("SM2SigSM3: got 0x%04x, want 0x0708", polluxTLS13GM.SM2SigSM3)
	}
}

func TestBlackBox_TLS13GM_SuiteName(t *testing.T) {
	tests := []struct {
		id   uint16
		want string
	}{
		{polluxTLS13GM.TLS_SM4_GCM_SM3, "TLS_SM4_GCM_SM3"},
		{polluxTLS13GM.TLS_SM4_CCM_SM3, "TLS_SM4_CCM_SM3"},
		{0x9999, "unknown"},
	}
	for _, tt := range tests {
		got := polluxTLS13GM.SuiteName(tt.id)
		if got != tt.want {
			t.Errorf("SuiteName(0x%04x): got %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestBlackBox_TLS13GM_HKDFExpandLabel(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	out, err := polluxTLS13GM.HKDFExpandLabel(secret, "key", nil, 16)
	if err != nil {
		t.Fatalf("HKDFExpandLabel: %v", err)
	}
	if len(out) != 16 {
		t.Errorf("output length: got %d, want 16", len(out))
	}
}

func TestBlackBox_TLS13GM_DeriveSecret(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	out, err := polluxTLS13GM.DeriveSecret(secret, "c hs traffic", []byte("transcript"))
	if err != nil {
		t.Fatalf("DeriveSecret: %v", err)
	}
	if len(out) != 32 {
		t.Errorf("output length: got %d, want 32", len(out))
	}
}

func TestBlackBox_TLS13GM_SM4GCM_AEAD_RoundTrip(t *testing.T) {
	key, _ := polluxSM4GCM.GenerateKey(rand.Reader)
	fixedNonce := make([]byte, 12)
	_, _ = rand.Read(fixedNonce)

	aead := polluxTLS13GM.NewAEAD(key, fixedNonce)
	plaintext := []byte("tls13gm AEAD test payload")
	aad := []byte("tls13 record")

	ct, err := aead.Seal(0, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	pt, err := aead.Open(0, ct, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("roundtrip: got %q, want %q", pt, plaintext)
	}
}

func TestBlackBox_TLS13GM_SM4GCM_TamperRejected(t *testing.T) {
	key, _ := polluxSM4GCM.GenerateKey(rand.Reader)
	fixedNonce := make([]byte, 12)
	_, _ = rand.Read(fixedNonce)

	aead := polluxTLS13GM.NewAEAD(key, fixedNonce)
	ct, _ := aead.Seal(0, []byte("secret"), nil)

	ct[0] ^= 0xff
	_, err := aead.Open(0, ct, nil)
	if err == nil {
		t.Error("tampered ciphertext should fail")
	}
}

func TestBlackBox_TLS13GM_SM4GCM_DifferentSeqNum(t *testing.T) {
	key, _ := polluxSM4GCM.GenerateKey(rand.Reader)
	fixedNonce := make([]byte, 12)
	_, _ = rand.Read(fixedNonce)

	aead := polluxTLS13GM.NewAEAD(key, fixedNonce)
	pt := []byte("sequence test")

	ct0, _ := aead.Seal(0, pt, nil)
	ct1, _ := aead.Seal(1, pt, nil)

	if bytes.Equal(ct0, ct1) {
		t.Error("different sequence numbers should produce different ciphertext")
	}

	dec0, err := aead.Open(0, ct0, nil)
	if err != nil || !bytes.Equal(dec0, pt) {
		t.Error("seq=0 decrypt should succeed")
	}
	dec1, err := aead.Open(1, ct1, nil)
	if err != nil || !bytes.Equal(dec1, pt) {
		t.Error("seq=1 decrypt should succeed")
	}
}
