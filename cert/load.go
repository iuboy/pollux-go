package cert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	polluxSm2 "github.com/iuboy/pollux-go/sm2"
	polluxSmx509 "github.com/iuboy/pollux-go/smx509"
)

// LoadKeyPairPEM loads a TLS certificate from PEM-encoded cert and key.
// Supports RSA, ECDSA, Ed25519, and SM2 keys.
func LoadKeyPairPEM(certPEM, keyPEM []byte) (tls.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return tls.Certificate{}, ErrInvalidPEM
	}

	key, err := polluxSm2.ParsePrivateKeyFromPEM(keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cert: parse private key: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{block.Bytes},
		PrivateKey:  key,
	}, nil
}

// LoadKeyPairFiles loads a TLS certificate from cert and key files.
func LoadKeyPairFiles(certFile, keyFile string) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cert: read cert file: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cert: read key file: %w", err)
	}
	return LoadKeyPairPEM(certPEM, keyPEM)
}

// DualCertificate holds a TLCP sign/encrypt certificate pair.
type DualCertificate struct {
	Sign tls.Certificate
	Enc  tls.Certificate
}

// LoadDualCertificatePEM loads a TLCP dual certificate pair from PEM bytes.
func LoadDualCertificatePEM(signCertPEM, signKeyPEM, encCertPEM, encKeyPEM []byte) (*DualCertificate, error) {
	sign, err := LoadKeyPairPEM(signCertPEM, signKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("cert: load sign cert: %w", err)
	}
	enc, err := LoadKeyPairPEM(encCertPEM, encKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("cert: load enc cert: %w", err)
	}
	return &DualCertificate{Sign: sign, Enc: enc}, nil
}

// LoadDualCertificateFiles loads a TLCP dual certificate pair from files.
func LoadDualCertificateFiles(signCertFile, signKeyFile, encCertFile, encKeyFile string) (*DualCertificate, error) {
	sign, err := LoadKeyPairFiles(signCertFile, signKeyFile)
	if err != nil {
		return nil, err
	}
	enc, err := LoadKeyPairFiles(encCertFile, encKeyFile)
	if err != nil {
		return nil, err
	}
	return &DualCertificate{Sign: sign, Enc: enc}, nil
}

// ParseCertificateRequest parses a DER-encoded certificate signing request.
func ParseCertificateRequest(der []byte) (*x509.CertificateRequest, error) {
	return polluxSmx509.ParseCertificateRequest(der)
}
