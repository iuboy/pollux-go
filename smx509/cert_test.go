package smx509

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
)

func generateSM2Cert(t *testing.T) (*x509.Certificate, *sm2.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	sm2Priv := new(sm2.PrivateKey)
	if _, err := sm2Priv.FromECPrivateKey(priv); err != nil {
		t.Fatalf("convert SM2 key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour * 24),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	der, err := CreateCertificate(tmpl, tmpl, &priv.PublicKey, sm2Priv)
	if err != nil {
		t.Fatalf("CreateCertificate SM2: %v", err)
	}

	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, sm2Priv
}

func TestIsSM2Key(t *testing.T) {
	_, sm2Priv := generateSM2Cert(t)
	if !IsSM2Key(sm2Priv) {
		t.Error("sm2.PrivateKey should be recognized as SM2")
	}

	ecdsaPriv, _ := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if !IsSM2Key(ecdsaPriv) {
		t.Error("ecdsa.PrivateKey on SM2 curve should be recognized as SM2")
	}

	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if IsSM2Key(rsaPriv) {
		t.Error("RSA key should not be recognized as SM2")
	}
}

func TestIsSM2PublicKey(t *testing.T) {
	_, sm2Priv := generateSM2Cert(t)
	if !IsSM2PublicKey(&sm2Priv.PublicKey) {
		t.Error("SM2 public key should be recognized")
	}

	ecdsaPriv, _ := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if !IsSM2PublicKey(&ecdsaPriv.PublicKey) {
		t.Error("ECDSA public key on SM2 curve should be recognized")
	}

	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if IsSM2PublicKey(rsaPriv.Public()) {
		t.Error("RSA public key should not be recognized as SM2")
	}
}

func TestParseCertificate_SM2(t *testing.T) {
	cert, _ := generateSM2Cert(t)
	if cert == nil {
		t.Fatal("cert should not be nil")
	}
	if cert.Subject.CommonName != "test" {
		t.Errorf("CommonName: got %q, want %q", cert.Subject.CommonName, "test")
	}
}

func TestParseCertificate_InvalidDER(t *testing.T) {
	_, err := ParseCertificate([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Error("should reject invalid DER")
	}
}

func TestCreateCertificate_RSA(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "rsa-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := CreateCertificate(tmpl, tmpl, &rsaPriv.PublicKey, rsaPriv)
	if err != nil {
		t.Fatalf("CreateCertificate RSA: %v", err)
	}
	if len(der) == 0 {
		t.Error("DER should not be empty")
	}
}

func TestExtractPublicKey(t *testing.T) {
	_, sm2Priv := generateSM2Cert(t)
	pub, err := ExtractPublicKey(sm2Priv)
	if err != nil {
		t.Fatalf("ExtractPublicKey SM2: %v", err)
	}
	if pub == nil {
		t.Error("public key should not be nil")
	}

	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub, err = ExtractPublicKey(rsaPriv)
	if err != nil {
		t.Fatalf("ExtractPublicKey RSA: %v", err)
	}
	if pub == nil {
		t.Error("public key should not be nil")
	}

	_, ed25519Priv, _ := ed25519.GenerateKey(rand.Reader)
	_, err = ExtractPublicKey(ed25519Priv)
	if err != nil {
		t.Fatalf("ExtractPublicKey Ed25519: %v", err)
	}
}

func TestSignatureAlgorithmForPrivateKey(t *testing.T) {
	_, sm2Priv := generateSM2Cert(t)
	if algo := SignatureAlgorithmForPrivateKey(sm2Priv); algo != x509.UnknownSignatureAlgorithm {
		t.Errorf("SM2 should return UnknownSignatureAlgorithm, got %v", algo)
	}

	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if algo := SignatureAlgorithmForPrivateKey(rsaPriv); algo != x509.SHA256WithRSA {
		t.Errorf("RSA 2048 should return SHA256WithRSA, got %v", algo)
	}

	ecdsaPriv, _ := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if algo := SignatureAlgorithmForPrivateKey(ecdsaPriv); algo != x509.UnknownSignatureAlgorithm {
		t.Errorf("SM2 curve ECDSA should return UnknownSignatureAlgorithm, got %v", algo)
	}
}

func TestPublicKeyAlgorithmForPrivateKey(t *testing.T) {
	_, sm2Priv := generateSM2Cert(t)
	if algo := PublicKeyAlgorithmForPrivateKey(sm2Priv); algo != x509.ECDSA {
		t.Errorf("SM2 should return ECDSA, got %v", algo)
	}

	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if algo := PublicKeyAlgorithmForPrivateKey(rsaPriv); algo != x509.RSA {
		t.Errorf("RSA should return RSA, got %v", algo)
	}
}

func TestMarshalPKIXPublicKey(t *testing.T) {
	_, sm2Priv := generateSM2Cert(t)
	der, err := MarshalPKIXPublicKey(&sm2Priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	if len(der) == 0 {
		t.Error("DER should not be empty")
	}
}

func TestMarshalParseECPrivateKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}

	parsed, err := ParseECPrivateKey(der)
	if err != nil {
		t.Fatalf("ParseECPrivateKey: %v", err)
	}
	if parsed.X.Cmp(priv.X) != 0 || parsed.Y.Cmp(priv.Y) != 0 {
		t.Error("parsed key mismatch")
	}
}
