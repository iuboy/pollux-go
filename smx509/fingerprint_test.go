package smx509

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/sm2"
)

func TestFingerprintSHA256_SM2Cert(t *testing.T) {
	key, _ := sm2.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKey:             key.Public(),
	}
	der, err := CreateCertificate(tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	fp := FingerprintSHA256(cert)
	if len(fp) != 64 { // 32 bytes hex
		t.Errorf("fingerprint length = %d, want 64", len(fp))
	}
	if FingerprintSHA256(cert) != fp {
		t.Error("fingerprint should be deterministic")
	}
}

func TestFingerprintSHA256_NilCert(t *testing.T) {
	if got := FingerprintSHA256(nil); got != "" {
		t.Errorf("FingerprintSHA256(nil) = %q, want empty", got)
	}
}

func TestFingerprintHash_SHA1(t *testing.T) {
	key, _ := sm2.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKey:             key.Public(),
	}
	der, _ := CreateCertificate(tmpl, tmpl, key.Public(), key)
	cert, _ := ParseCertificate(der)

	fp, err := FingerprintHash(cert, crypto.SHA1)
	if err != nil {
		t.Fatalf("FingerprintHash SHA1: %v", err)
	}
	if len(fp) != 40 { // 20 bytes hex
		t.Errorf("SHA1 fingerprint length = %d, want 40", len(fp))
	}
}

func TestFingerprintHash_NilCert(t *testing.T) {
	fp, err := FingerprintHash(nil, crypto.SHA256)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp != "" {
		t.Errorf("expected empty fingerprint for nil cert, got %q", fp)
	}
}
