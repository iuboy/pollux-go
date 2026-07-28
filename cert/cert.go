package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	polluxSmx509 "github.com/iuboy/pollux-go/smx509"
)

// Kind represents the type of certificate.
type Kind int

const (
	// KindUnknown indicates the certificate type could not be determined.
	KindUnknown Kind = iota
	// KindStandard is a standard X.509 certificate (RSA, ECDSA, Ed25519).
	KindStandard
	// KindSM2 is an SM2 (national cryptography) X.509 certificate.
	KindSM2
)

// DetectKind detects whether a certificate uses SM2 or standard algorithms.
func DetectKind(cert *x509.Certificate) Kind {
	if cert == nil {
		return KindUnknown
	}
	if polluxSmx509.IsSM2PublicKey(cert.PublicKey) {
		return KindSM2
	}
	return KindStandard
}

// IsSM2Certificate reports whether the certificate uses an SM2 public key.
func IsSM2Certificate(cert *x509.Certificate) bool {
	return DetectKind(cert) == KindSM2
}

// ParseCertificate parses a DER-encoded certificate.
// It automatically selects the correct backend (standard x509 or smx509).
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	return polluxSmx509.ParseCertificate(der)
}

// ParseCertificatePEM parses a PEM-encoded certificate.
// Rejects non-CERTIFICATE PEM block types (e.g. private key PEM) to avoid
// confusing ASN.1 parse errors downstream.
func ParseCertificatePEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, ErrInvalidPEM
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("cert: unexpected PEM block type %q, want CERTIFICATE", block.Type)
	}
	return ParseCertificate(block.Bytes)
}

// ParseCertificatesPEM parses multiple PEM-encoded certificates.
//
// On a mid-stream parse failure the function returns the certificates parsed
// SO FAR (non-nil slice) together with the error, rather than discarding them
// via `return nil, err`. This matches the de-facto TLS bundle-loading
// convention (a caller assembling a chain from a multi-cert PEM can still use
// the successfully-parsed prefix while reporting the bad block) and avoids
// the surprising data loss of the previous early-return form. Callers that
// want strict all-or-nothing semantics should check len(certs) against the
// expected count or re-encode the bundle.
//
// Non-CERTIFICATE PEM blocks (PRIVATE KEY, etc.) are silently skipped —
// matching x509.CertPool.AppendCertsFromPEM.
func ParseCertificatesPEM(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := ParseCertificate(block.Bytes)
		if err != nil {
			// Return the partial result + the error so the caller can decide
			// whether to use the prefix. Wrapping identifies which block
			// (by 1-based index among CERTIFICATE-typed blocks) failed.
			return certs, fmt.Errorf("cert: parse certificate block #%d: %w", len(certs)+1, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
