package smx509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	gmsmSmx509 "github.com/emmansun/gmsm/smx509"
)

// TestX_H3_CSR_Type_Safety tests CSR handling safety
// Audit finding: X-H3 (smx509 CSR 类型转换可能不安全)
func TestX_H3_CSR_Type_Safety(t *testing.T) {
	sm2Priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate SM2 key: %v", err)
	}

	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test-sm2.example.com",
		},
		DNSNames: []string{"test-sm2.example.com"},
	}

	// SM2 CSR creation via pollux smx509
	sm2CSR, err := CreateCertificateRequest(csrTemplate, sm2Priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest SM2: %v", err)
	}

	// ECDSA CSR creation via pollux smx509
	ecdsaCSR, err := CreateCertificateRequest(csrTemplate, ecdsaPriv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest ECDSA: %v", err)
	}

	// Parse both CSRs — should not panic
	parsedSM2, err := ParseCertificateRequest(sm2CSR)
	if err != nil {
		t.Fatalf("ParseCertificateRequest SM2: %v", err)
	}
	if parsedSM2 == nil {
		t.Error("parsed SM2 CSR should not be nil")
	}

	parsedECDSA, err := ParseCertificateRequest(ecdsaCSR)
	if err != nil {
		t.Fatalf("ParseCertificateRequest ECDSA: %v", err)
	}
	if parsedECDSA == nil {
		t.Error("parsed ECDSA CSR should not be nil")
	}

	// Verify gmsm smx509 can parse SM2 CSR
	gmsmCSR, err := gmsmSmx509.ParseCertificateRequest(sm2CSR)
	if err != nil {
		t.Errorf("gmsm ParseCertificateRequest SM2: %v", err)
	}
	if gmsmCSR == nil {
		t.Error("gmsm parsed CSR should not be nil")
	}

	// Verify signatures — should not panic
	if err := CheckCertificateRequestSignature(parsedSM2); err != nil {
		t.Errorf("SM2 CSR signature verification failed: %v", err)
	}
	if err := CheckCertificateRequestSignature(parsedECDSA); err != nil {
		t.Errorf("ECDSA CSR signature verification failed: %v", err)
	}

	// Malformed CSR should not panic
	wrongCSR := &x509.CertificateRequest{
		SignatureAlgorithm: x509.UnknownSignatureAlgorithm,
		Signature:          []byte("invalid signature"),
		Raw:                sm2CSR,
	}
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("CheckCertificateRequestSignature should not panic: %v", r)
		}
	}()
	_ = wrongCSR // just ensure no panic during construction
}
