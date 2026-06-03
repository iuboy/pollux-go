package smx509

import (
	"crypto"
	"crypto/x509"
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

// ParseOCSPResponse parses a DER-encoded OCSP response.
func ParseOCSPResponse(data []byte) (*ocsp.Response, error) {
	return ocsp.ParseResponse(data, nil)
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
