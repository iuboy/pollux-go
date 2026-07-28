package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func generateTestCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, priv
}

func TestPool_AddAndGet(t *testing.T) {
	pool := NewPool()
	if pool.Len() != 0 {
		t.Error("new pool should be empty")
	}

	cert, _ := generateTestCert(t)
	pool.AddCert(cert)
	if pool.Len() != 1 {
		t.Error("pool should have 1 cert")
	}

	certs := pool.Certificates()
	if len(certs) != 1 {
		t.Error("Certificates should return 1 cert")
	}
	raw := pool.RawDER()
	if len(raw) != 1 || len(raw[0]) == 0 {
		t.Error("RawDER should return non-empty DER")
	}

	stdPool := pool.ToStandardPool()
	if stdPool == nil {
		t.Error("ToStandardPool should not return nil")
	}

	smxPool := pool.ToSMX509Pool()
	if smxPool == nil {
		t.Error("ToSMX509Pool should not return nil")
	}
}

func TestPool_AppendCertsFromPEM(t *testing.T) {
	pool := NewPool()
	cert, _ := generateTestCert(t)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	if !pool.AppendCertsFromPEM(pemData) {
		t.Error("AppendCertsFromPEM should return true for valid PEM")
	}
	if pool.Len() != 1 {
		t.Error("pool should have 1 cert after PEM append")
	}

	emptyPool := NewPool()
	if emptyPool.AppendCertsFromPEM([]byte("not PEM")) {
		t.Error("AppendCertsFromPEM should return false for invalid PEM")
	}
}

func TestDetectKind_Standard(t *testing.T) {
	cert, _ := generateTestCert(t)
	if DetectKind(cert) != KindStandard {
		t.Error("ECDSA P-256 cert should be KindStandard")
	}
	if IsSM2Certificate(cert) {
		t.Error("ECDSA cert should not be SM2")
	}
}

func TestDetectKind_Nil(t *testing.T) {
	if DetectKind(nil) != KindUnknown {
		t.Error("nil cert should be KindUnknown")
	}
}

func TestParseCertificatePEM(t *testing.T) {
	cert, _ := generateTestCert(t)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	parsed, err := ParseCertificatePEM(pemData)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	if parsed == nil {
		t.Error("parsed cert should not be nil")
	}
}

func TestParseCertificatePEM_Invalid(t *testing.T) {
	_, err := ParseCertificatePEM([]byte("not PEM"))
	if err != ErrInvalidPEM {
		t.Errorf("expected ErrInvalidPEM, got %v", err)
	}
}

func TestParseCertificatesPEM(t *testing.T) {
	cert, _ := generateTestCert(t)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	certs, err := ParseCertificatesPEM(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 cert, got %d", len(certs))
	}
}

func TestVerifyCertificate_NoRoots(t *testing.T) {
	cert, _ := generateTestCert(t)
	err := VerifyCertificate(cert, VerifyOptions{})
	if err != ErrNoRoots {
		t.Errorf("expected ErrNoRoots, got %v", err)
	}
}

func TestVerifyCertificate_NilCert(t *testing.T) {
	err := VerifyCertificate(nil, VerifyOptions{Roots: NewPool()})
	if err != ErrUnsupportedCert {
		t.Errorf("expected ErrUnsupportedCert, got %v", err)
	}
}

func TestVerifyCertificate_SelfSignedWithRoot(t *testing.T) {
	cert, _ := generateTestCert(t)
	roots := NewPoolFromCerts(cert)

	err := VerifyCertificate(cert, VerifyOptions{Roots: roots})
	if err != nil {
		t.Errorf("self-signed cert with itself as root should succeed: %v", err)
	}
}

func TestNewPoolFromCerts(t *testing.T) {
	cert, _ := generateTestCert(t)
	pool := NewPoolFromCerts(cert)
	if pool.Len() != 1 {
		t.Error("NewPoolFromCerts should have 1 cert")
	}
}

func TestPool_NilCert(t *testing.T) {
	pool := NewPool()
	pool.AddCert(nil)
	if pool.Len() != 0 {
		t.Error("adding nil cert should not increase pool size")
	}
}
