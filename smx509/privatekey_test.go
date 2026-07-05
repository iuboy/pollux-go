package smx509

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/iuboy/pollux-go/sm2"
)

func TestParsePrivateKeyPEM_SM2(t *testing.T) {
	key, _ := sm2.GenerateKey(rand.Reader)
	der, _ := sm2.MarshalPKCS8PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	parsed, err := ParsePrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM SM2: %v", err)
	}
	if _, ok := parsed.(*sm2.PrivateKey); !ok {
		t.Errorf("expected *sm2.PrivateKey, got %T", parsed)
	}
}

// TestParsePrivateKeyPEM_SM2_SEC1 covers the SM2 SEC1 ("EC PRIVATE KEY")
// detection path. We build the SEC1 PEM by marshaling via gmsm-compatible
// path: pollux-go/sm2 exposes WritePrivateKeyToPEM (PKCS#8 only), so we
// cannot easily synthesize a SM2 SEC1 PEM here. The SM2 SEC1 detection is
// already tested in pollux-go/sm2; here we only verify the PKCS#8 SM2 path
// (TestParsePrivateKeyPEM_SM2). This test is a no-op placeholder documenting
// the gap.
func TestParsePrivateKeyPEM_SM2_SEC1(t *testing.T) {
	t.Skip("SM2 SEC1 PEM synthesis requires gmsm internals; covered by pollux-go/sm2 tests")
}

func TestParsePrivateKeyPEM_ECDSA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := MarshalPrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: PEMTypeForPrivateKey(key), Bytes: der})

	parsed, err := ParsePrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM ECDSA: %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePrivateKeyPEM_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := MarshalPrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: PEMTypeForPrivateKey(key), Bytes: der})

	parsed, err := ParsePrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM RSA: %v", err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePrivateKeyPEM_Ed25519(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := MarshalPrivateKey(priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: PEMTypeForPrivateKey(priv), Bytes: der})

	parsed, err := ParsePrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM Ed25519: %v", err)
	}
	if _, ok := parsed.(ed25519.PrivateKey); !ok {
		t.Errorf("expected ed25519.PrivateKey, got %T", parsed)
	}
}

func TestParsePrivateKeyPEM_Invalid(t *testing.T) {
	if _, err := ParsePrivateKeyPEM([]byte("not pem")); err == nil {
		t.Error("expected error for non-PEM input")
	}
	if _, err := ParsePrivateKeyPEM(nil); err == nil {
		t.Error("expected error for nil input")
	}
}

func TestMarshalPrivateKey_SM2_PKCS8RoundTrip(t *testing.T) {
	key, _ := sm2.GenerateKey(rand.Reader)
	der, err := MarshalPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPrivateKey SM2: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: PEMTypeForPrivateKey(key), Bytes: der})
	if string(pemBytes[:len("-----BEGIN PRIVATE KEY")]) != "-----BEGIN PRIVATE KEY" {
		t.Fatalf("SM2 PEM type should be PRIVATE KEY (PKCS#8), got: %q", pemBytes[:40])
	}
	parsed, err := ParsePrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("round-trip ParsePrivateKeyPEM: %v", err)
	}
	parsedSM2, ok := parsed.(*sm2.PrivateKey)
	if !ok {
		t.Fatalf("expected *sm2.PrivateKey, got %T", parsed)
	}
	if parsedSM2.D.Cmp(key.D) != 0 {
		t.Error("round-trip D mismatch")
	}
}

func TestMarshalPrivateKey_Unsupported(t *testing.T) {
	if _, err := MarshalPrivateKey("not a key"); err == nil {
		t.Error("expected error for unsupported type")
	}
}

func TestPEMTypeForPrivateKey(t *testing.T) {
	sm2Key, _ := sm2.GenerateKey(rand.Reader)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name string
		key  any
		want string
	}{
		{"SM2", sm2Key, "PRIVATE KEY"},
		{"ECDSA", ecdsaKey, "EC PRIVATE KEY"},
		{"RSA", rsaKey, "PRIVATE KEY"},
		{"Ed25519", edPriv, "PRIVATE KEY"},
		{"unknown", big.NewInt(1), "PRIVATE KEY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PEMTypeForPrivateKey(tt.key); got != tt.want {
				t.Errorf("PEMTypeForPrivateKey(%s) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}
