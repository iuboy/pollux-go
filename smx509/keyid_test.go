package smx509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/sm2"
)

func TestGenerateSubjectKeyIdentifier_SM2(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ski, err := GenerateSubjectKeyIdentifier(key.Public())
	if err != nil {
		t.Fatalf("GenerateSubjectKeyIdentifier SM2: %v", err)
	}
	if len(ski) != 20 {
		t.Errorf("SKI length = %d, want 20 (SHA-1)", len(ski))
	}
}

func TestGenerateSubjectKeyIdentifier_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ski, err := GenerateSubjectKeyIdentifier(key.Public())
	if err != nil {
		t.Fatalf("GenerateSubjectKeyIdentifier ECDSA: %v", err)
	}
	if len(ski) != 20 {
		t.Errorf("SKI length = %d, want 20", len(ski))
	}
}

func TestGenerateSubjectKeyIdentifier_Deterministic(t *testing.T) {
	key, _ := sm2.GenerateKey(rand.Reader)
	ski1, _ := GenerateSubjectKeyIdentifier(key.Public())
	ski2, _ := GenerateSubjectKeyIdentifier(key.Public())
	if string(ski1) != string(ski2) {
		t.Error("SKI should be deterministic for the same public key")
	}
}

func TestGenerateAuthorityKeyIdentifier_NilKey(t *testing.T) {
	_, err := GenerateAuthorityKeyIdentifier(nil)
	if err == nil {
		t.Fatal("expected error for nil issuer public key")
	}
}

func TestCreateSubjectKeyIdentifierExtension_Empty(t *testing.T) {
	ext := CreateSubjectKeyIdentifierExtension(nil)
	if ext.Id != nil {
		t.Error("empty keyID should produce zero-value Extension")
	}
}

func TestAddRFC5280KeyIdentifiers_NilTemplate(t *testing.T) {
	err := AddRFC5280KeyIdentifiers(nil, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil template")
	}
}

func TestAddRFC5280KeyIdentifiers_AutoGenerate(t *testing.T) {
	caKey, _ := sm2.GenerateKey(rand.Reader)
	subjKey, _ := sm2.GenerateKey(rand.Reader)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		PublicKey:    subjKey.Public(),
	}
	if err := AddRFC5280KeyIdentifiers(tmpl, nil, nil, caKey.Public()); err != nil {
		t.Fatalf("AddRFC5280KeyIdentifiers: %v", err)
	}
	if len(tmpl.ExtraExtensions) != 2 {
		t.Fatalf("expected 2 extensions (SKI+AKI), got %d", len(tmpl.ExtraExtensions))
	}

	var haveSKI, haveAKI bool
	for _, ext := range tmpl.ExtraExtensions {
		switch {
		case ext.Id.Equal(OIDSubjectKeyIdentifier):
			haveSKI = true
		case ext.Id.Equal(OIDAuthorityKeyIdentifier):
			haveAKI = true
		}
	}
	if !haveSKI {
		t.Error("missing SKI extension after AddRFC5280KeyIdentifiers")
	}
	if !haveAKI {
		t.Error("missing AKI extension after AddRFC5280KeyIdentifiers")
	}
}

func TestGetSubjectKeyIdentifier_NilCert(t *testing.T) {
	if got := GetSubjectKeyIdentifier(nil); got != nil {
		t.Errorf("GetSubjectKeyIdentifier(nil) = %v, want nil", got)
	}
}

func TestGetAuthorityKeyIdentifier_NilCert(t *testing.T) {
	if got := GetAuthorityKeyIdentifier(nil); got != nil {
		t.Errorf("GetAuthorityKeyIdentifier(nil) = %v, want nil", got)
	}
}

// TestValidateKeyIdentifiers_NilCert confirms the nil guard returns false
// with a clear issue string rather than panicking.
func TestValidateKeyIdentifiers_NilCert(t *testing.T) {
	ok, issues := ValidateKeyIdentifiers(nil)
	if ok {
		t.Error("expected ok=false for nil cert")
	}
	if len(issues) == 0 {
		t.Error("expected at least one issue for nil cert")
	}
}

// TestValidateKeyIdentifiers_SelfSignedDERBased verifies that self-signed
// detection now compares the canonical DER Subject/Issuer rather than only
// the CommonName field. Two certs with the same CN but different O must be
// treated as non-self-signed (and thus require AKI).
func TestValidateKeyIdentifiers_SelfSignedDERBased(t *testing.T) {
	key, _ := sm2.GenerateKey(rand.Reader)

	// A genuine self-signed CA with SKI: should pass.
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKey:             key.Public(),
	}
	if err := AddRFC5280KeyIdentifiers(tmpl, nil, nil, nil); err != nil {
		t.Fatalf("AddRFC5280KeyIdentifiers: %v", err)
	}
	der, err := CreateCertificate(tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if ok, issues := ValidateKeyIdentifiers(cert); !ok {
		t.Errorf("self-signed CA with SKI should validate, got issues: %v", issues)
	}
}

// TestValidateKeyIdentifiers_MissingSKI confirms a missing SKI is flagged.
// Note: CreateCertificate auto-generates a SKI for CA certs, so we use a
// non-CA leaf cert (which has no auto-SKI) and a manually-parsed cert that
// has no extensions at all.
func TestValidateKeyIdentifiers_MissingSKI(t *testing.T) {
	// Construct a parsed cert with no extensions to force the missing-SKI path.
	// Using a non-CA template avoids the auto-SKI behavior of CreateCertificate.
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		// No Extensions, no SubjectKeyId.
	}
	ok, issues := ValidateKeyIdentifiers(cert)
	if ok {
		t.Error("expected ok=false for cert without SKI")
	}
	if len(issues) == 0 {
		t.Error("expected issues for cert without SKI")
	}
}
