package smx509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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

	respBytes, err := CreateOCSPResponse(caCert, caCert, tmpl, caKey)
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
		Status:           ocsp.Revoked,
		SerialNumber:     big.NewInt(99),
		ThisUpdate:       time.Now().UTC(),
		NextUpdate:       time.Now().Add(time.Hour).UTC(),
		RevokedAt:        revokeTime,
		RevocationReason: ocsp.KeyCompromise,
		Certificate:      caCert,
	}

	respBytes, err := CreateOCSPResponse(caCert, caCert, tmpl, caKey)
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
	respBytes, err := CreateOCSPResponse(caCert, caCert, tmpl, caKey)
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

// TestParseOCSPResponseWithIssuer_SM2 verifies the SM2-aware verification path:
// ParseOCSPResponseWithIssuer must succeed for SM2-signed responses (previously
// failed with "x509: unsupported elliptic curve" via stdlib ocsp.ParseResponse).
func TestParseOCSPResponseWithIssuer_SM2(t *testing.T) {
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

	tmpl := &ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(42),
		ThisUpdate:   time.Now().UTC(),
		NextUpdate:   time.Now().Add(time.Hour).UTC(),
		Certificate:  caCert,
	}
	respBytes, err := CreateOCSPResponse(caCert, caCert, tmpl, caKey)
	if err != nil {
		t.Fatalf("CreateOCSPResponse SM2: %v", err)
	}

	// This previously failed via stdlib ocsp.ParseResponse.
	parsed, err := ParseOCSPResponseWithIssuer(respBytes, caCert)
	if err != nil {
		t.Fatalf("ParseOCSPResponseWithIssuer SM2: %v", err)
	}
	if parsed.Status != ocsp.Good {
		t.Errorf("status = %v, want Good", parsed.Status)
	}
	if parsed.SerialNumber.Cmp(big.NewInt(42)) != 0 {
		t.Errorf("serial = %v, want 42", parsed.SerialNumber)
	}
	if parsed.IssuerHash != crypto.SHA256 {
		t.Errorf("IssuerHash = %v, want SHA256", parsed.IssuerHash)
	}
}

// TestParseOCSPResponseWithIssuer_SM2_Revoked covers the Revoked branch.
func TestParseOCSPResponseWithIssuer_SM2_Revoked(t *testing.T) {
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

	tmpl := &ocsp.Response{
		Status:           ocsp.Revoked,
		SerialNumber:     big.NewInt(99),
		ThisUpdate:       time.Now().UTC(),
		NextUpdate:       time.Now().Add(time.Hour).UTC(),
		RevokedAt:        time.Now().Add(-time.Minute).UTC(),
		RevocationReason: ocsp.KeyCompromise,
		Certificate:      caCert,
	}
	respBytes, _ := CreateOCSPResponse(caCert, caCert, tmpl, caKey)

	parsed, err := ParseOCSPResponseWithIssuer(respBytes, caCert)
	if err != nil {
		t.Fatalf("ParseOCSPResponseWithIssuer SM2 revoked: %v", err)
	}
	if parsed.Status != ocsp.Revoked {
		t.Errorf("status = %v, want Revoked", parsed.Status)
	}
	if parsed.RevocationReason != ocsp.KeyCompromise {
		t.Errorf("reason = %v, want KeyCompromise", parsed.RevocationReason)
	}
}

// TestParseOCSPResponseWithIssuer_NilIssuer confirms the API still requires
// an issuer (no parse-only mode).
func TestParseOCSPResponseWithIssuer_NilIssuer(t *testing.T) {
	_, err := ParseOCSPResponseWithIssuer([]byte{0x30, 0x03, 0x0a, 0x01, 0x00}, nil)
	if err == nil {
		t.Fatal("expected error for nil issuer")
	}
}

// TestParseOCSPResponseWithIssuer_Tampered verifies that a tampered signature
// is rejected by the SM2 verification path.
func TestParseOCSPResponseWithIssuer_Tampered(t *testing.T) {
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

	tmpl := &ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(42),
		ThisUpdate:   time.Now().UTC(),
		NextUpdate:   time.Now().Add(time.Hour).UTC(),
		Certificate:  caCert,
	}
	respBytes, _ := CreateOCSPResponse(caCert, caCert, tmpl, caKey)

	// Flip a byte near the end (likely in the signature region).
	if len(respBytes) > 10 {
		respBytes[len(respBytes)-10] ^= 0xFF
	}
	_, err := ParseOCSPResponseWithIssuer(respBytes, caCert)
	if err == nil {
		t.Fatal("expected error for tampered SM2 OCSP response")
	}
}

// TestParseOCSPResponseWithIssuer_DelegatedResponder_EKU covers RFC 6960
// §4.2.2.2: an embedded delegated responder cert (a leaf distinct from the
// issuer, signed by the issuer) MUST carry id-kp-OCSPSigning. A cert lacking
// the EKU must be rejected; one carrying it must be accepted.
func TestParseOCSPResponseWithIssuer_DelegatedResponder_EKU(t *testing.T) {
	// Issuer / CA.
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

	// Delegated responder key + two certs: one with EKU, one without.
	respKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		PublicKey:    respKey.Public(),
	}
	noEKUDER, err := CreateCertificate(base, caTmpl, respKey.Public(), caKey)
	if err != nil {
		t.Fatalf("CreateCertificate delegated w/o EKU: %v", err)
	}
	noEKUCert, err := ParseCertificate(noEKUDER)
	if err != nil {
		t.Fatalf("ParseCertificate delegated w/o EKU: %v", err)
	}

	withEKUTmpl := *base
	withEKUTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	withEKUDER, err := CreateCertificate(&withEKUTmpl, caTmpl, respKey.Public(), caKey)
	if err != nil {
		t.Fatalf("CreateCertificate delegated w/ EKU: %v", err)
	}
	withEKUCert, err := ParseCertificate(withEKUDER)
	if err != nil {
		t.Fatalf("ParseCertificate delegated w/ EKU: %v", err)
	}

	tmplNoEKU := &ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(42),
		ThisUpdate:   time.Now().UTC(),
		NextUpdate:   time.Now().Add(time.Hour).UTC(),
		Certificate:  noEKUCert, // embedded delegated responder cert (no EKU)
	}
	tmplWithEKU := &ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(42),
		ThisUpdate:   time.Now().UTC(),
		NextUpdate:   time.Now().Add(time.Hour).UTC(),
		Certificate:  withEKUCert, // embedded delegated responder cert (w/ EKU)
	}

	// Without EKU: rejected even though the responder key is valid for the
	// signature and the cert was issued by the CA.
	respNoEKU, err := CreateOCSPResponse(noEKUCert, caCert, tmplNoEKU, respKey)
	if err != nil {
		t.Fatalf("CreateOCSPResponse delegated w/o EKU: %v", err)
	}
	if _, err := ParseOCSPResponseWithIssuer(respNoEKU, caCert); err == nil {
		t.Fatal("expected rejection of delegated responder cert lacking OCSPSigning EKU")
	}

	// With EKU: accepted.
	respWithEKU, err := CreateOCSPResponse(withEKUCert, caCert, tmplWithEKU, respKey)
	if err != nil {
		t.Fatalf("CreateOCSPResponse delegated w/ EKU: %v", err)
	}
	parsed, err := ParseOCSPResponseWithIssuer(respWithEKU, caCert)
	if err != nil {
		t.Fatalf("ParseOCSPResponseWithIssuer delegated w/ EKU: %v", err)
	}
	if parsed.Status != ocsp.Good {
		t.Errorf("status = %v, want Good", parsed.Status)
	}
}

// TestParseOCSPResponseWithIssuer_ResponderIDMismatch verifies RFC 6960
// §4.2.2.2 enforcement: a response whose ResponderID does not match the
// embedded signing certificate MUST be rejected.
//
// Attack modeled: an attacker (or compromised responder) holds the SAME SM2
// private key under two different subjects — certA (CN=responder-A) and certB
// (CN=responder-B), both issued by the CA with OCSPSigning EKU. They sign an
// OCSP response with that shared key, set ResponderID = A's subject, but embed
// certB. The signature verifies against certB (same key), and certB carries
// the EKU — without ResponderID matching the parser would accept the response
// as if it came from B, even though the response itself claims A authored it.
// This breaks the identity binding RFC 6960 §4.2.2.2 mandates.
func TestParseOCSPResponseWithIssuer_ResponderIDMismatch(t *testing.T) {
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

	// One shared key, two distinct-subject certs (key reuse = the attack
	// surface ResponderID matching defends against).
	sharedKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mkCert := func(serial *big.Int, cn string) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			PublicKey:    sharedKey.Public(),
			Subject:      pkix.Name{CommonName: cn},
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		}
		der, err := CreateCertificate(tmpl, caTmpl, sharedKey.Public(), caKey)
		if err != nil {
			t.Fatal(err)
		}
		c, err := ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	certA := mkCert(big.NewInt(10), "responder-A")
	certB := mkCert(big.NewInt(11), "responder-B")

	// Sign with the shared key, set CreateOCSPResponse responder=certA so the
	// ResponderID becomes A's subject, but embed certB via template.Certificate.
	// The signature is computed over the TBS (whose ResponderID = A), using the
	// shared key — so it verifies against BOTH certA and certB. The parser only
	// sees certB: signature OK, EKU OK, but ResponderID (A) ≠ certB subject.
	tmpl := &ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(42),
		ThisUpdate:   time.Now().UTC(),
		NextUpdate:   time.Now().Add(time.Hour).UTC(),
		Certificate:  certB,
	}
	resp, err := CreateOCSPResponse(certA, caCert, tmpl, sharedKey)
	if err != nil {
		t.Fatalf("CreateOCSPResponse: %v", err)
	}
	_, err = ParseOCSPResponseWithIssuer(resp, caCert)
	if err == nil {
		t.Fatal("expected rejection of response whose ResponderID does not match embedded cert")
	}
}
