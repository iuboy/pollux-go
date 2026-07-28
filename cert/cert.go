package cert

import (
	"crypto/x509"
	"encoding/pem"

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
func ParseCertificatePEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, ErrInvalidPEM
	}
	return ParseCertificate(block.Bytes)
}

// ParseCertificatesPEM parses multiple PEM-encoded certificates.
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
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
