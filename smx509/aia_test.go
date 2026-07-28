package smx509

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/sm2"
)

func TestCreateAuthorityInfoAccessExtension_OCSPAndCAIssuers(t *testing.T) {
	ext, err := CreateAuthorityInfoAccessExtension(
		[]string{"http://ocsp.example.com"},
		[]string{"http://ca.example.com/issuer.crt"},
	)
	if err != nil {
		t.Fatalf("CreateAuthorityInfoAccessExtension: %v", err)
	}
	if !ext.Id.Equal(OIDAuthorityInfoAccess) {
		t.Errorf("ext.Id = %v, want AIA OID", ext.Id)
	}
	if ext.Critical {
		t.Error("AIA extension should be non-critical")
	}
}

func TestCreateAuthorityInfoAccessExtension_Empty(t *testing.T) {
	ext, err := CreateAuthorityInfoAccessExtension(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ext.Id != nil {
		t.Errorf("expected zero extension, got %+v", ext)
	}
}

func TestCreateAuthorityInfoAccessExtension_RoundTrip(t *testing.T) {
	// Build a cert with AIA and parse it back.
	key, _ := sm2.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKey:             key.Public(),
	}
	aiaExt, err := CreateAuthorityInfoAccessExtension(
		[]string{"http://ocsp.example.com"},
		[]string{"http://ca.example.com/ca.crt"},
	)
	if err != nil {
		t.Fatalf("CreateAIA: %v", err)
	}
	tmpl.ExtraExtensions = []pkix.Extension{aiaExt}

	der, err := CreateCertificate(tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	ocsp, caIssuers := GetAuthorityInfoAccess(cert)
	if len(ocsp) != 1 || ocsp[0] != "http://ocsp.example.com" {
		t.Errorf("OCSP URLs = %v, want [http://ocsp.example.com]", ocsp)
	}
	if len(caIssuers) != 1 || caIssuers[0] != "http://ca.example.com/ca.crt" {
		t.Errorf("CA Issuers URLs = %v, want [http://ca.example.com/ca.crt]", caIssuers)
	}
}

func TestGetAuthorityInfoAccess_NoAIA(t *testing.T) {
	key, _ := sm2.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		PublicKey:    key.Public(),
	}
	der, _ := CreateCertificate(tmpl, tmpl, key.Public(), key)
	cert, _ := ParseCertificate(der)

	ocsp, caIssuers := GetAuthorityInfoAccess(cert)
	if ocsp != nil || caIssuers != nil {
		t.Errorf("expected nil slices for cert without AIA, got ocsp=%v caIssuers=%v", ocsp, caIssuers)
	}
}

func TestCreateCRLDistributionPointsExtension(t *testing.T) {
	ext, err := CreateCRLDistributionPointsExtension([]string{"http://crl.example.com/ca.crl"})
	if err != nil {
		t.Fatalf("CreateCRLDistributionPointsExtension: %v", err)
	}
	if !ext.Id.Equal(OIDCRLDistributionPoints) {
		t.Errorf("ext.Id = %v, want CRLDP OID", ext.Id)
	}
}

func TestCreateCRLDistributionPointsExtension_Empty(t *testing.T) {
	ext, err := CreateCRLDistributionPointsExtension(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ext.Id != nil {
		t.Errorf("expected zero extension, got %+v", ext)
	}
}

func TestGetAuthorityInfoAccess_NilCert(t *testing.T) {
	ocsp, caIssuers := GetAuthorityInfoAccess(nil)
	if ocsp != nil || caIssuers != nil {
		t.Error("expected nil for nil cert")
	}
}
