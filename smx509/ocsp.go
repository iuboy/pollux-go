package smx509

import (
	"crypto"
	"crypto/x509"
	"errors"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSP status codes, mirroring golang.org/x/crypto/ocsp constants.
const (
	OCSPGood    = ocsp.Good
	OCSPRevoked = ocsp.Revoked
	OCSPUnknown = ocsp.Unknown
)

// CreateOCSPResponse creates an OCSP response signed by the responder.
// If the responder key is SM2, the response is signed with SM2+SM3.
func CreateOCSPResponse(template *ocsp.Response, responderCert *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	return ocsp.CreateResponse(responderCert, responderCert, *template, signer)
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
func ParseOCSPResponse(data []byte) (*ocsp.Response, error) {
	return ocsp.ParseResponse(data, nil)
}

// ParseOCSPResponseWithIssuer parses and verifies a DER-encoded OCSP response.
// The issuer certificate is used to verify the OCSP response signature.
// For SM2-signed responses, pass the SM2 issuer certificate.
//
// Returns an error if issuer is nil, as signature verification would be skipped.
func ParseOCSPResponseWithIssuer(data []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
	if issuer == nil {
		return nil, errors.New("smx509: issuer certificate is required for OCSP response verification")
	}
	return ocsp.ParseResponse(data, issuer)
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
