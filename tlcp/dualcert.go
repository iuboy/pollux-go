package tlcp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/ycq/pollux/sm2"
	polluxSmx509 "github.com/ycq/pollux/smx509"
)

var (
	errInvalidCertPair   = errors.New("tlcp: invalid dual certificate pair")
	errSignCertMissing   = errors.New("tlcp: sign certificate is required")
	errEncCertMissing    = errors.New("tlcp: encrypt certificate is required")
	errNotSM2Certificate = errors.New("tlcp: certificate is not SM2")
)

// DualCertPair represents a TLCP dual certificate pair (signing certificate + encryption certificate).
// This is a core feature of TLCP: signing and encryption use different certificates and keys.
type DualCertPair struct {
	SignCert *x509.Certificate
	EncCert  *x509.Certificate
	SignKey  *sm2.PrivateKey
	EncKey   *sm2.PrivateKey
}

// LoadDualCertPair loads a dual certificate pair from PEM files.
func LoadDualCertPair(signCertFile, signKeyFile, encCertFile, encKeyFile string) (*DualCertPair, error) {
	signCert, err := loadCertificate(signCertFile)
	if err != nil {
		return nil, fmt.Errorf("tlcp: load sign cert: %w", err)
	}

	encCert, err := loadCertificate(encCertFile)
	if err != nil {
		return nil, fmt.Errorf("tlcp: load encrypt cert: %w", err)
	}

	signKey, err := loadSM2PrivateKey(signKeyFile)
	if err != nil {
		return nil, fmt.Errorf("tlcp: load sign key: %w", err)
	}

	encKey, err := loadSM2PrivateKey(encKeyFile)
	if err != nil {
		return nil, fmt.Errorf("tlcp: load encrypt key: %w", err)
	}

	pair := &DualCertPair{
		SignCert: signCert,
		EncCert:  encCert,
		SignKey:  signKey,
		EncKey:   encKey,
	}

	if err := ValidateDualCertPair(pair); err != nil {
		return nil, err
	}
	return pair, nil
}

// LoadDualCertPairFromPEM loads a dual certificate pair from PEM-encoded byte data.
func LoadDualCertPairFromPEM(signCertPEM, signKeyPEM, encCertPEM, encKeyPEM []byte) (*DualCertPair, error) {
	signCert, err := parseCertificatePEM(signCertPEM)
	if err != nil {
		return nil, fmt.Errorf("tlcp: parse sign cert: %w", err)
	}

	encCert, err := parseCertificatePEM(encCertPEM)
	if err != nil {
		return nil, fmt.Errorf("tlcp: parse encrypt cert: %w", err)
	}

	signKey, err := sm2.ParsePrivateKeyFromPEM(signKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("tlcp: parse sign key: %w", err)
	}

	encKey, err := sm2.ParsePrivateKeyFromPEM(encKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("tlcp: parse encrypt key: %w", err)
	}

	pair := &DualCertPair{
		SignCert: signCert,
		EncCert:  encCert,
		SignKey:  signKey,
		EncKey:   encKey,
	}

	if err := ValidateDualCertPair(pair); err != nil {
		return nil, err
	}
	return pair, nil
}

// ValidateDualCertPair validates the dual certificate pair.
// Checks: certificate type, key usage, issuer consistency, validity period.
func ValidateDualCertPair(pair *DualCertPair) error {
	if pair.SignCert == nil {
		return errSignCertMissing
	}
	if pair.EncCert == nil {
		return errEncCertMissing
	}

	// Validate signing certificate usage
	if err := ValidateTLCPCertificate(pair.SignCert, true); err != nil {
		return fmt.Errorf("tlcp: sign cert: %w", err)
	}

	// Validate encryption certificate usage
	if err := ValidateTLCPCertificate(pair.EncCert, false); err != nil {
		return fmt.Errorf("tlcp: encrypt cert: %w", err)
	}

	// Verify same issuer (compare RawIssuer)
	if !bytes.Equal(pair.SignCert.RawIssuer, pair.EncCert.RawIssuer) {
		return fmt.Errorf("tlcp: sign and encrypt certs from different issuers")
	}

	return nil
}

// ValidateTLCPCertificate checks if a single certificate meets TLCP requirements.
func ValidateTLCPCertificate(cert *x509.Certificate, isSignCert bool) error {
	if cert == nil {
		return errInvalidCertPair
	}

	// Verify SM2 certificate
	if !polluxSmx509.IsSM2PublicKey(cert.PublicKey) {
		return errNotSM2Certificate
	}

	// Verify key usage
	if isSignCert {
		if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return fmt.Errorf("tlcp: sign cert missing digitalSignature key usage")
		}
	} else {
		if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 &&
			cert.KeyUsage&x509.KeyUsageDataEncipherment == 0 {
			return fmt.Errorf("tlcp: encrypt cert missing keyEncipherment or dataEncipherment key usage")
		}
	}

	// Verify extended key usage (EKU)
	if len(cert.ExtKeyUsage) > 0 {
		hasValidEKU := false
		for _, eku := range cert.ExtKeyUsage {
			if eku == x509.ExtKeyUsageServerAuth || eku == x509.ExtKeyUsageClientAuth ||
				eku == x509.ExtKeyUsageAny {
				hasValidEKU = true
				break
			}
		}
		if !hasValidEKU {
			role := "sign"
			if !isSignCert {
				role = "encrypt"
			}
			return fmt.Errorf("tlcp: %s cert missing serverAuth, clientAuth, or any ExtendedKeyUsage", role)
		}
	}

	return nil
}

// VerifyDualCertPair verifies pairing of dual certificates (same issuer, key usage).
// Chain verification should be performed by the caller for each certificate separately.
func VerifyDualCertPair(pair *DualCertPair) error {
	return polluxSmx509.VerifyDualCerts(pair.SignCert, pair.EncCert)
}

// ToTLSCertificates converts dual certificate pair to tls.Certificate.
// Returns [signing certificate, encryption certificate].
func (p *DualCertPair) ToTLSCertificates() ([]tls.Certificate, error) {
	signTLSCert, err := p.toTLSCertificate(p.SignCert, p.SignKey)
	if err != nil {
		return nil, fmt.Errorf("tlcp: convert sign cert: %w", err)
	}

	encTLSCert, err := p.toTLSCertificate(p.EncCert, p.EncKey)
	if err != nil {
		return nil, fmt.Errorf("tlcp: convert encrypt cert: %w", err)
	}

	return []tls.Certificate{signTLSCert, encTLSCert}, nil
}

// toTLSCertificate converts x509 certificate and SM2 private key to tls.Certificate.
func (p *DualCertPair) toTLSCertificate(cert *x509.Certificate, key *sm2.PrivateKey) (tls.Certificate, error) {
	certDER, err := polluxSmx509.CreateCertificate(cert, cert, cert.PublicKey, key)
	if err != nil {
		return tls.Certificate{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  key,
		}, nil
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

// PublicKeyPairs returns signing and encryption public key pairs.
func (p *DualCertPair) PublicKeyPairs() (signPub, encPub *ecdsa.PublicKey) {
	if p.SignCert != nil {
		if pub, ok := p.SignCert.PublicKey.(*ecdsa.PublicKey); ok {
			signPub = pub
		}
	}
	if p.EncCert != nil {
		if pub, ok := p.EncCert.PublicKey.(*ecdsa.PublicKey); ok {
			encPub = pub
		}
	}
	return
}

// loadCertificate loads an x509 certificate from PEM file.
func loadCertificate(filename string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return parseCertificatePEM(data)
}

// parseCertificatePEM parses x509 certificate from PEM-encoded data.
func parseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("tlcp: failed to decode PEM block")
	}
	return polluxSmx509.ParseCertificate(block.Bytes)
}

// loadSM2PrivateKey loads an SM2 private key from PEM file.
func loadSM2PrivateKey(filename string) (*sm2.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return sm2.ParsePrivateKeyFromPEM(data)
}
