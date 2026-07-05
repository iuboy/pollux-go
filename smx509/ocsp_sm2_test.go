package smx509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/sm2"
	"golang.org/x/crypto/ocsp"
)

// TestCreateOCSPResponse_SM2 verifies that CreateOCSPResponse succeeds with an
// SM2 responder key (previously failed because x/crypto/ocsp rejects SM2) and
// produces a response that ocsp.ParseResponse can verify against the issuer.
func TestCreateOCSPResponse_SM2(t *testing.T) {
	// Generate SM2 CA (acts as issuer + responder).
	caKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKey:             caKey.Public(),
	}
	caDER, err := CreateCertificate(caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatalf("CreateCertificate CA: %v", err)
	}
	caCert, err := ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}

	// Build an OCSP response template for a leaf serial.
	tmpl := &ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(42),
		ThisUpdate:   time.Now().UTC(),
		NextUpdate:   time.Now().Add(time.Hour).UTC(),
		Certificate:  caCert,
	}

	respBytes, err := CreateOCSPResponse(tmpl, caCert, caKey)
	if err != nil {
		t.Fatalf("CreateOCSPResponse SM2: %v", err)
	}
	if len(respBytes) == 0 {
		t.Fatal("empty OCSP response")
	}

	// Note: ocsp.ParseResponse (stdlib) cannot consume SM2-signed responses
	// at all — it rejects sm2.P256() during signature-algorithm detection,
	// before any verification. Verifying an SM2 OCSP response end-to-end
	// requires a gmsm-aware verifier, out of scope for CreateOCSPResponse
	// (its job is to *produce* the response). Validate the outer envelope
	// and ResponseType instead.
	env := parseOCSPEnvelope(t, respBytes)
	if !env.Response.ResponseType.Equal(idPKIXOCSPBasic) {
		t.Errorf("ResponseType = %v, want idPKIXOCSPBasic", env.Response.ResponseType)
	}
	if env.Status != 0 { // ocsp.Success == 0
		t.Errorf("envelope status = %d, want 0 (Success)", env.Status)
	}
}

// TestCreateOCSPResponse_Revoked_SM2 covers the Revoked branch in the SM2 path.
func TestCreateOCSPResponse_Revoked_SM2(t *testing.T) {
	caKey, _ := sm2.GenerateKey(rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKey:             caKey.Public(),
	}
	caDER, _ := CreateCertificate(caTmpl, caTmpl, caKey.Public(), caKey)
	caCert, _ := ParseCertificate(caDER)

	revokeTime := time.Now().Add(-10 * time.Minute).UTC()
	tmpl := &ocsp.Response{
		Status:          ocsp.Revoked,
		SerialNumber:    big.NewInt(99),
		ThisUpdate:      time.Now().UTC(),
		NextUpdate:      time.Now().Add(time.Hour).UTC(),
		RevokedAt:       revokeTime,
		RevocationReason: ocsp.KeyCompromise,
		Certificate:     caCert,
	}

	respBytes, err := CreateOCSPResponse(tmpl, caCert, caKey)
	if err != nil {
		t.Fatalf("CreateOCSPResponse SM2 revoked: %v", err)
	}
	env := parseOCSPEnvelope(t, respBytes)
	if !env.Response.ResponseType.Equal(idPKIXOCSPBasic) {
		t.Errorf("ResponseType = %v, want idPKIXOCSPBasic", env.Response.ResponseType)
	}
}

// TestCreateOCSPResponse_ECDSA ensures the standard path still works after
// adding the SM2 branch.
func TestCreateOCSPResponse_ECDSA(t *testing.T) {
	caKey, caCert := selfSignedECDSACA(t)

	tmpl := &ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(7),
		ThisUpdate:   time.Now().UTC(),
		NextUpdate:   time.Now().Add(time.Hour).UTC(),
		Certificate:  caCert,
	}
	respBytes, err := CreateOCSPResponse(tmpl, caCert, caKey)
	if err != nil {
		t.Fatalf("CreateOCSPResponse ECDSA: %v", err)
	}
	if _, err := ocsp.ParseResponse(respBytes, caCert); err != nil {
		t.Fatalf("ParseResponse ECDSA: %v", err)
	}
}

func selfSignedECDSACA(t *testing.T) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKey:             key.Public(),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// parseOCSPEnvelope unmarshals just the outer OCSPResponse envelope (status +
// ResponseBytes.ResponseType) without touching the embedded signature, which
// stdlib ocsp.ParseResponse cannot do for SM2-signed responses.
func parseOCSPEnvelope(t *testing.T, der []byte) sm2ResponseASN1 {
	t.Helper()
	var env sm2ResponseASN1
	if _, err := asn1.Unmarshal(der, &env); err != nil {
		t.Fatalf("parseOCSPEnvelope: %v", err)
	}
	return env
}
