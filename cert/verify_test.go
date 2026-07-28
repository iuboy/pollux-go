package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	polluxSM2 "github.com/iuboy/pollux-go/sm2"
	polluxSmx509 "github.com/iuboy/pollux-go/smx509"
)

// generateSM2TestCert issues a self-signed SM2 CA certificate whose raw DER
// carries the SM2 OID so IsSM2Certificate reports true. Its ExtKeyUsage is
// restricted to ServerAuth so validateKeyUsages can be exercised for both the
// matching and the mismatching cases.
func generateSM2TestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	ecPriv, err := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	sm2Priv := new(polluxSM2.PrivateKey)
	if _, err := sm2Priv.FromECPrivateKey(ecPriv); err != nil {
		t.Fatalf("convert SM2 key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "sm2-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"sm2.test"},
	}
	der, err := polluxSmx509.CreateCertificate(tmpl, tmpl, &ecPriv.PublicKey, sm2Priv)
	if err != nil {
		t.Fatalf("CreateCertificate SM2: %v", err)
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate SM2: %v", err)
	}
	return cert
}

// TestVerifyCertificate_SM2SelfSigned drives the SM2 verification path
// (verifySM2) end to end: a self-signed SM2 certificate that is also its own
// root must verify successfully.
func TestVerifyCertificate_SM2SelfSigned(t *testing.T) {
	cert := generateSM2TestCert(t)
	if !IsSM2Certificate(cert) {
		t.Fatal("expected an SM2 certificate to exercise verifySM2")
	}
	roots := NewPoolFromCerts(cert)
	if err := VerifyCertificate(cert, VerifyOptions{Roots: roots}); err != nil {
		t.Errorf("SM2 self-signed cert with itself as root should succeed: %v", err)
	}
}

// TestVerifyCertificate_SM2TimeValidation covers the manual time checks in
// verifySM2 (gmsm/smx509 does not honor CurrentTime), for both the
// not-yet-valid and expired branches.
func TestVerifyCertificate_SM2TimeValidation(t *testing.T) {
	cert := generateSM2TestCert(t)
	roots := NewPoolFromCerts(cert)

	t.Run("not yet valid", func(t *testing.T) {
		past := time.Now().Add(-48 * time.Hour)
		err := VerifyCertificate(cert, VerifyOptions{Roots: roots, CurrentTime: past})
		if err == nil || !strings.Contains(err.Error(), "not yet valid") {
			t.Errorf("expected not-yet-valid error, got %v", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		future := time.Now().Add(48 * time.Hour)
		err := VerifyCertificate(cert, VerifyOptions{Roots: roots, CurrentTime: future})
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Errorf("expected expired error, got %v", err)
		}
	})
}

// TestVerifyCertificate_KeyUsages exercises validateKeyUsages: a matching
// required usage is accepted, a mismatching one is rejected.
func TestVerifyCertificate_KeyUsages(t *testing.T) {
	cert := generateSM2TestCert(t) // ExtKeyUsage restricted to ServerAuth
	roots := NewPoolFromCerts(cert)

	if err := VerifyCertificate(cert, VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("matching EKU should succeed: %v", err)
	}

	err := VerifyCertificate(cert, VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	if err == nil {
		t.Errorf("expected EKU mismatch error, got nil")
	}
}

// TestValidateKeyUsages_AnyEKU covers the ExtKeyUsageAny fast path: a cert
// advertising Any accepts any required usage.
func TestValidateKeyUsages_AnyEKU(t *testing.T) {
	cert := generateSM2TestCert(t)
	cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	if err := validateKeyUsages(cert, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}); err != nil {
		t.Errorf("ExtKeyUsageAny should accept any required usage: %v", err)
	}
}

// generateLeafTestCert issues a self-signed non-CA (leaf) ECDSA certificate. It
// intentionally lacks IsCA so it can be used to assert leaf-as-root rejection.
func generateLeafTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return cert
}

// TestVerifyCertificate_LeafAsRootRejected verifies that a non-CA leaf
// certificate placed in the trust roots is rejected with ErrLeafAsRoot, rather
// than being accepted as its own trust anchor.
func TestVerifyCertificate_LeafAsRootRejected(t *testing.T) {
	leaf := generateLeafTestCert(t)
	if leaf.IsCA {
		t.Fatal("setup: expected a non-CA leaf certificate")
	}
	roots := NewPoolFromCerts(leaf)
	err := VerifyCertificate(leaf, VerifyOptions{Roots: roots})
	if !errors.Is(err, ErrLeafAsRoot) {
		t.Errorf("expected ErrLeafAsRoot for leaf-as-root, got %v", err)
	}
}

// TestVerifyCertificate_MixedRootsRejected verifies that a single non-CA cert
// mixed into otherwise-valid CA roots still triggers ErrLeafAsRoot.
func TestVerifyCertificate_MixedRootsRejected(t *testing.T) {
	ca, _ := generateTestCert(t) // IsCA=true after the helper fix
	leaf := generateLeafTestCert(t)
	roots := NewPoolFromCerts(ca, leaf)
	err := VerifyCertificate(ca, VerifyOptions{Roots: roots})
	if !errors.Is(err, ErrLeafAsRoot) {
		t.Errorf("expected ErrLeafAsRoot when roots contain a leaf, got %v", err)
	}
}
