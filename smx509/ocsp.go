package smx509

import (
	"crypto"
	"crypto/x509"
	"errors"
	"time"

	"github.com/iuboy/pollux-go/sm2"
	"golang.org/x/crypto/ocsp"
)

// OCSP status codes, mirroring golang.org/x/crypto/ocsp constants.
const (
	OCSPGood    = ocsp.Good
	OCSPRevoked = ocsp.Revoked
	OCSPUnknown = ocsp.Unknown
)

// CreateOCSPResponse creates an OCSP response signed by the responder.
// If signer is an SM2 private key, the response is signed with SM2+SM3
// (GM/T 0009-2012) via createSM2OCSPResponse; otherwise it delegates to
// golang.org/x/crypto/ocsp.CreateResponse, which cannot handle SM2 keys
// (its signingParamsForPublicKey rejects sm2.P256()).
//
// issuer is the CA whose key issued the certificate being responded about (used
// to compute the CertID name/key hashes). responderCert is the certificate
// whose private key signs the response; it MAY equal issuer (CA-direct
// responder) or be a delegated responder cert signed by issuer.
func CreateOCSPResponse(issuer, responderCert *x509.Certificate, template *ocsp.Response, signer crypto.Signer) ([]byte, error) {
	if issuer == nil {
		return nil, errors.New("smx509: issuer certificate is required to compute the OCSP CertID")
	}
	if responderCert == nil {
		return nil, errors.New("smx509: responder certificate is required to sign the OCSP response")
	}
	if template == nil {
		return nil, errors.New("smx509: OCSP response template is required")
	}
	if sm2Key, ok := signer.(*sm2.PrivateKey); ok {
		return createSM2OCSPResponse(issuer, responderCert, *template, sm2Key)
	}
	return ocsp.CreateResponse(issuer, responderCert, *template, signer)
}

// ParseOCSPRequest parses a DER-encoded OCSP request.
func ParseOCSPRequest(data []byte) (*ocsp.Request, error) {
	return ocsp.ParseRequest(data)
}

// ParseOCSPResponse parses a DER-encoded OCSP response WITHOUT signature verification.
//
// Deprecated: this function does not verify the OCSP response signature,
// allowing an attacker to forge a "Good" status. Use ParseOCSPResponseWithIssuer
// instead, which validates the signature against the issuer certificate.
// For legitimate parse-only use cases (logging, debugging, already-verified
// responses), use ParseOCSPResponseUnverified, whose name makes the security
// trade-off explicit at the call site.
func ParseOCSPResponse(data []byte) (*ocsp.Response, error) {
	return ParseOCSPResponseUnverified(data)
}

// ParseOCSPResponseUnverified parses a DER-encoded OCSP response WITHOUT
// signature verification. The returned Response MUST NOT be trusted for
// security decisions — without verification, an attacker can forge an
// arbitrary status (Good/Revoked/Unknown).
//
// This is intended only for:
//   - Logging/inspection of a response that has already been verified by
//     ParseOCSPResponseWithIssuer in the same request.
//   - Debugging/test tooling that intentionally inspects untrusted input.
//
// For any security-relevant code path, use ParseOCSPResponseWithIssuer.
func ParseOCSPResponseUnverified(data []byte) (*ocsp.Response, error) {
	return ocsp.ParseResponse(data, nil)
}

// ParseOCSPResponseWithIssuer parses and verifies a DER-encoded OCSP response.
// The issuer certificate is used to verify the OCSP response signature.
//
// For SM2-signed responses, the SM2-aware verification path is used (the
// stdlib ocsp.ParseResponse rejects sm2.P256() with "unsupported elliptic
// curve"); for standard algorithms, it delegates to ocsp.ParseResponse.
//
// In addition to signature verification, this function enforces a
// validity-period check: the response is rejected if NextUpdate has passed or
// ThisUpdate is in the future (beyond a small clock-skew tolerance). A
// signature-valid but stale response can otherwise be replayed to mask a
// revocation. Use ParseOCSPResponseWithIssuerAt to supply a reference time
// (e.g. for testing or a fixed verification instant).
//
// Returns an error if issuer is nil, as signature verification would be skipped.
func ParseOCSPResponseWithIssuer(data []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
	return ParseOCSPResponseWithIssuerAt(data, issuer, time.Now())
}

// ParseOCSPResponseWithIssuerAt is like ParseOCSPResponseWithIssuer but uses
// the supplied now as the reference time for the validity-period check. Pass
// time.Time{} (the zero value) to disable the time check — intended only for
// parsing already-trusted or historical responses where staleness is not
// meaningful.
func ParseOCSPResponseWithIssuerAt(data []byte, issuer *x509.Certificate, now time.Time) (*ocsp.Response, error) {
	if issuer == nil {
		return nil, errors.New("smx509: issuer certificate is required for OCSP response verification")
	}
	if isSM2OCSPResponse(data) {
		return parseSM2OCSPResponse(data, issuer, now)
	}
	// Non-SM2 responses are delegated to x/crypto/ocsp, which does not enforce
	// a time check. Apply the same validity-period policy here for consistency.
	resp, err := ocsp.ParseResponse(data, issuer)
	if err != nil {
		return nil, err
	}
	if !now.IsZero() {
		if !resp.ThisUpdate.IsZero() && now.Add(ocspFreshnessLeeway).Before(resp.ThisUpdate) {
			return nil, errors.New("smx509: OCSP response ThisUpdate is in the future")
		}
		if !resp.NextUpdate.IsZero() && now.After(resp.NextUpdate) {
			return nil, errors.New("smx509: OCSP response is stale (past NextUpdate)")
		}
	}
	return resp, nil
}

// NewOCSPResponseTemplate creates an OCSP response template for a certificate.
func NewOCSPResponseTemplate(cert, issuer *x509.Certificate, status int, thisUpdate, nextUpdate time.Time) ocsp.Response {
	return ocsp.Response{
		Status:       status,
		SerialNumber: cert.SerialNumber,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
		Certificate:  issuer,
	}
}
