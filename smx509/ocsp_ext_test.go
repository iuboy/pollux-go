package smx509

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/sm2"
	"golang.org/x/crypto/ocsp"
)

// makeResponderKey generates a self-signed responder CA for the given key
// type (used as both issuer and responderCert, CA-direct mode). Non-SM2 keys
// go through the pure stdlib path: gmsm's smx509 fork (the backend behind
// this package's ParseCertificate) does not recognize the Ed25519 signature
// OID, which would surface as "algorithm unimplemented" when x/crypto's
// ParseResponse later runs CheckSignatureFrom on the embedded certificate.
func makeResponderKey(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Responder"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	var (
		der []byte
		err error
	)
	if IsSM2Key(key) {
		der, err = CreateCertificate(tmpl, tmpl, key.Public(), key)
	} else {
		der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	}
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	var cert *x509.Certificate
	if IsSM2Key(key) {
		cert, err = ParseCertificate(der)
	} else {
		cert, err = x509.ParseCertificate(der)
	}
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// TestCreateOCSPResponseExt_SM2_NonceRoundTrip covers the SM2 path: the
// nonce round-trips through ResponseNonce and the response parses with the
// package's own verifier (signature + validity period).
func TestCreateOCSPResponseExt_SM2_NonceRoundTrip(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := makeResponderKey(t, key)
	now := time.Now().UTC()
	nonce := []byte("nonce-echo-012345")

	der, err := CreateOCSPResponseExt(cert, cert, &OCSPResponseParams{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(42),
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
		Certificate:  cert,
		IssuerHash:   crypto.SHA256,
		Nonce:        nonce,
	}, key)
	if err != nil {
		t.Fatalf("CreateOCSPResponseExt: %v", err)
	}

	got, err := ResponseNonce(der)
	if err != nil {
		t.Fatalf("ResponseNonce: %v", err)
	}
	if !bytes.Equal(got, nonce) {
		t.Fatalf("nonce mismatch: got %q want %q", got, nonce)
	}

	resp, err := ParseOCSPResponseWithIssuerAt(der, cert, now)
	if err != nil {
		t.Fatalf("ParseOCSPResponseWithIssuerAt: %v", err)
	}
	if resp.Status != ocsp.Good || resp.SerialNumber.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("parsed response mismatch: status=%v serial=%v", resp.Status, resp.SerialNumber)
	}
}

// TestCreateOCSPResponseExt_StandardSigners covers the non-SM2 dispatch:
// responses signed by ECDSA P-256/P-384, RSA and Ed25519 keys must verify
// with x/crypto's parser, and the nonce must round-trip.
func TestCreateOCSPResponseExt_StandardSigners(t *testing.T) {
	nonce := []byte("std-nonce-abcdef")

	newKey := func(t *testing.T, kind string) crypto.Signer {
		t.Helper()
		switch kind {
		case "ecdsa256":
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return k
		case "ecdsa384":
			k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return k
		case "rsa":
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			return k
		case "ed25519":
			_, k, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return k
		}
		t.Fatalf("unknown kind %q", kind)
		return nil
	}

	for _, kind := range []string{"ecdsa256", "ecdsa384", "rsa"} {
		t.Run(kind, func(t *testing.T) {
			key := newKey(t, kind)
			cert := makeResponderKey(t, key)
			now := time.Now().UTC()

			der, err := CreateOCSPResponseExt(cert, cert, &OCSPResponseParams{
				Status:       ocsp.Good,
				SerialNumber: big.NewInt(7),
				ThisUpdate:   now,
				NextUpdate:   now.Add(time.Hour),
				Certificate:  cert,
				Nonce:        nonce,
			}, key)
			if err != nil {
				t.Fatalf("CreateOCSPResponseExt(%s): %v", kind, err)
			}

			// x/crypto must parse AND verify the signature (interop contract).
			resp, err := ocsp.ParseResponse(der, cert)
			if err != nil {
				t.Fatalf("x/crypto ParseResponse(%s): %v", kind, err)
			}
			if resp.Status != ocsp.Good {
				t.Fatalf("status = %v, want Good", resp.Status)
			}

			got, err := ResponseNonce(der)
			if err != nil {
				t.Fatalf("ResponseNonce(%s): %v", kind, err)
			}
			if !bytes.Equal(got, nonce) {
				t.Fatalf("nonce mismatch (%s): got %q", kind, got)
			}
		})
	}

	// Ed25519: x/crypto's ParseResponse cannot VERIFY Ed25519-signed OCSP
	// responses (its signatureAlgorithmDetails table has no Ed25519 entry),
	// so the round-trip is verified directly — parse the envelope with the
	// package's own decoding structs and run ed25519.Verify over the raw
	// tbsResponseData.
	t.Run("ed25519", func(t *testing.T) {
		key := newKey(t, "ed25519").(ed25519.PrivateKey)
		cert := makeResponderKey(t, key)
		now := time.Now().UTC()

		der, err := CreateOCSPResponseExt(cert, cert, &OCSPResponseParams{
			Status:       ocsp.Good,
			SerialNumber: big.NewInt(7),
			ThisUpdate:   now,
			NextUpdate:   now.Add(time.Hour),
			Certificate:  cert,
			Nonce:        nonce,
		}, key)
		if err != nil {
			t.Fatalf("CreateOCSPResponseExt(ed25519): %v", err)
		}

		got, err := ResponseNonce(der)
		if err != nil {
			t.Fatalf("ResponseNonce(ed25519): %v", err)
		}
		if !bytes.Equal(got, nonce) {
			t.Fatalf("nonce mismatch (ed25519): got %q", got)
		}

		var outer extResponseASN1
		if _, err := asn1.Unmarshal(der, &outer); err != nil {
			t.Fatalf("unmarshal envelope: %v", err)
		}
		var basic parseBasicResponse
		if _, err := asn1.Unmarshal(outer.Response.Response, &basic); err != nil {
			t.Fatalf("unmarshal basicResponse: %v", err)
		}
		if !ed25519.Verify(key.Public().(ed25519.PublicKey),
			basic.TBSResponseData.Raw, basic.Signature.RightAlign()) {
			t.Fatal("ed25519.Verify failed over raw tbsResponseData")
		}
	})
}

// TestCreateOCSPResponseExt_ReasonOmitted asserts RFC 5280 §5.3.1 compliance:
// reason=unspecified(0) omits the revokedInfo reason field entirely, while a
// concrete reason encodes it. OCSP's revokedInfo.reason is a context-tagged
// ([0] EXPLICIT) field with no extension OID in the DER, so omission is
// asserted structurally: the reason=0 encoding is strictly shorter and both
// variants parse to their intended RevocationReason.
func TestCreateOCSPResponseExt_ReasonOmitted(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := makeResponderKey(t, key)
	now := time.Now().UTC()

	build := func(reason int) []byte {
		t.Helper()
		der, err := CreateOCSPResponseExt(cert, cert, &OCSPResponseParams{
			Status:           ocsp.Revoked,
			SerialNumber:     big.NewInt(9),
			ThisUpdate:       now,
			NextUpdate:       now.Add(time.Hour),
			RevokedAt:        now.Add(-time.Minute),
			RevocationReason: reason,
		}, key)
		if err != nil {
			t.Fatalf("CreateOCSPResponseExt(reason=%d): %v", reason, err)
		}
		return der
	}

	withZero := build(0)
	withReason := build(1) // keyCompromise (7 is unassigned and now rejected)
	if len(withZero) >= len(withReason) {
		t.Errorf("reason=0 DER (%d bytes) should be shorter than reason=1 (%d bytes) — reason field not omitted",
			len(withZero), len(withReason))
	}

	respZero, err := ParseOCSPResponseWithIssuerAt(withZero, cert, now)
	if err != nil {
		t.Fatalf("parse revoked(reason=0): %v", err)
	}
	if respZero.Status != ocsp.Revoked || respZero.RevocationReason != 0 {
		t.Fatalf("reason=0: status=%v reason=%v, want Revoked/0", respZero.Status, respZero.RevocationReason)
	}
	respOne, err := ParseOCSPResponseWithIssuerAt(withReason, cert, now)
	if err != nil {
		t.Fatalf("parse revoked(reason=1): %v", err)
	}
	if respOne.RevocationReason != 1 {
		t.Fatalf("reason=1: parsed reason=%d, want 1", respOne.RevocationReason)
	}
	// 未分配值 7 被构造侧拒绝(RFC 5280 §5.3.1):绕过 build 的 t.Fatalf
	// 包装直接断言错误返回。
	_, r7err := CreateOCSPResponseExt(cert, cert, &OCSPResponseParams{
		Status: ocsp.Revoked, SerialNumber: big.NewInt(9),
		ThisUpdate: now, NextUpdate: now.Add(time.Hour),
		RevokedAt: now.Add(-time.Minute), RevocationReason: 7,
	}, key)
	if r7err == nil {
		t.Error("unassigned reason 7 should be rejected at construction")
	}
}

// TestCreateOCSPResponse_ReasonOmitted_Legacy asserts the same §5.3.1 fix on
// the legacy template-based API (behavior change: reason=0 no longer encodes
// an explicit zero-valued reason). See the structural-omission note in
// TestCreateOCSPResponseExt_ReasonOmitted.
func TestCreateOCSPResponse_ReasonOmitted_Legacy(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := makeResponderKey(t, key)
	now := time.Now().UTC()

	build := func(reason int) []byte {
		t.Helper()
		der, err := CreateOCSPResponse(cert, cert, &ocsp.Response{
			Status:           ocsp.Revoked,
			SerialNumber:     big.NewInt(11),
			ThisUpdate:       now,
			NextUpdate:       now.Add(time.Hour),
			RevokedAt:        now.Add(-time.Minute),
			RevocationReason: reason,
		}, key)
		if err != nil {
			t.Fatalf("CreateOCSPResponse(reason=%d): %v", reason, err)
		}
		return der
	}

	withZero := build(0)
	withReason := build(1)
	if len(withZero) >= len(withReason) {
		t.Errorf("legacy reason=0 DER (%d bytes) should be shorter than reason=1 (%d bytes)",
			len(withZero), len(withReason))
	}
	resp, err := ParseOCSPResponseWithIssuerAt(withZero, cert, now)
	if err != nil {
		t.Fatalf("parse legacy revoked(reason=0): %v", err)
	}
	if resp.Status != ocsp.Revoked || resp.RevocationReason != 0 {
		t.Fatalf("status=%v reason=%v, want Revoked/0", resp.Status, resp.RevocationReason)
	}
}

// TestResponseNonce_MissingAndMalformed covers the parsing edge cases.
func TestResponseNonce_MissingAndMalformed(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := makeResponderKey(t, key)
	now := time.Now().UTC()

	noNonce, err := CreateOCSPResponseExt(cert, cert, &OCSPResponseParams{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(1),
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ResponseNonce(noNonce)
	if err != nil {
		t.Fatalf("ResponseNonce(no nonce): %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil nonce, got %q", got)
	}

	if _, err := ResponseNonce([]byte{0x30, 0x01}); err == nil {
		t.Error("malformed DER should error")
	}
	// responseStatus-only error response has no BasicResponse inside.
	if _, err := ResponseNonce(OCSPErrorResponse(1)); err == nil {
		t.Error("error-status response should not parse as BasicOCSPResponse")
	}
}

// TestExtractOCSPRequestNonce builds a request with a nonce extension by hand
// (x/crypto's Request.Marshal cannot emit requestExtensions) and asserts
// extraction.
func TestExtractOCSPRequestNonce(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := makeResponderKey(t, key)

	nonce := []byte("req-nonce-1234")
	nonceVal, _ := asn1.Marshal(nonce)
	type tbsRequestWithExts struct {
		RequestList       []asn1.RawValue  `asn1:"optional"`
		RequestExtensions []pkix.Extension `asn1:"explicit,tag:2,optional"`
	}
	reqDER, err := asn1.Marshal(struct {
		TBSRequest tbsRequestWithExts
	}{tbsRequestWithExts{
		RequestExtensions: []pkix.Extension{{Id: oidExtOCSPNonce, Value: nonceVal}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	got := ExtractOCSPRequestNonce(reqDER)
	if !bytes.Equal(got, nonce) {
		t.Fatalf("request nonce mismatch: got %q want %q", got, nonce)
	}

	// A nonce-free request must return nil (not error). Hand-assembled:
	// x/crypto's CreateRequest dereferences a nil cert template, so it cannot
	// produce the control case.
	type tbsRequestNoExts struct {
		RequestList []asn1.RawValue `asn1:"optional"`
	}
	plainDER, err := asn1.Marshal(struct {
		TBSRequest tbsRequestNoExts
	}{tbsRequestNoExts{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := ExtractOCSPRequestNonce(plainDER); got != nil {
		t.Fatalf("nonce-free request returned %q", got)
	}

	// Malformed input: nil, not a panic.
	if got := ExtractOCSPRequestNonce([]byte{0x30, 0x01}); got != nil {
		t.Fatalf("malformed request returned %q", got)
	}
	_ = cert
}

// TestOCSPErrorResponse asserts the responseStatus-only encoding is parseable
// by x/crypto as the corresponding error. Status 1 = malformedRequest
// (RFC 6960 §4.2.1; x/crypto exposes no named constant, only the
// MalformedRequestErrorResponse variable).
func TestOCSPErrorResponse(t *testing.T) {
	der := OCSPErrorResponse(1)
	if _, err := ocsp.ParseResponse(der, nil); err == nil {
		t.Fatal("x/crypto should report MalformedRequest for error-status response")
	}
}
