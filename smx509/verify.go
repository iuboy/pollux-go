package smx509

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"

	smx509 "github.com/emmansun/gmsm/smx509"
)

var (
	errMismatchedCA       = errors.New("smx509: sign and encrypt certificates not from same CA")
	errInvalidKeyUsage    = errors.New("smx509: incorrect key usage for certificate type")
	errMissingEncryptCert = errors.New("smx509: encrypt certificate required for dual certificate verification")
	errNoCertChain        = errors.New("smx509: no valid certificate chain")
	errSelfSignedLeaf     = errors.New("smx509: certificate is self-signed but not in root pool")
)

// VerifyOptions holds certificate verification options.
type VerifyOptions struct {
	DNSName       string
	Roots         *CertPool
	Intermediates *CertPool
	// KeyUsages specifies the extended key usages the certificate must satisfy.
	// If nil, defaults to ExtKeyUsageServerAuth (matching crypto/x509 default).
	// Set to []ExtKeyUsage{ExtKeyUsageClientAuth} when verifying client certs.
	KeyUsages []x509.ExtKeyUsage
}

// Verify verifies a certificate, automatically selecting the standard library
// or gmsm/smx509 backend based on the key type.
func Verify(cert *x509.Certificate, opts VerifyOptions) error {
	if cert == nil {
		return errors.New("smx509: nil certificate")
	}

	// Block leaf-as-root: if the cert is self-signed and not in Roots, reject.
	if cert.CheckSignatureFrom(cert) == nil {
		if opts.Roots == nil || !opts.Roots.contains(cert) {
			return errSelfSignedLeaf
		}
	}
	// Also guard SM2 self-signed leaves that CheckSignatureFrom cannot validate
	// (the standard library does not understand SM2 signatures, so it returns
	// a non-nil error and the guard above is silently bypassed).
	if IsSM2PublicKey(cert.PublicKey) &&
		bytes.Equal(cert.RawSubject, cert.RawIssuer) &&
		(opts.Roots == nil || !opts.Roots.contains(cert)) {
		return errSelfSignedLeaf
	}

	// Build standard x509.VerifyOptions from CertPool.
	verifyOpts := x509.VerifyOptions{
		DNSName:   opts.DNSName,
		KeyUsages: opts.KeyUsages,
	}
	if opts.Roots != nil {
		verifyOpts.Roots = opts.Roots.toStdCertPool()
	}
	if opts.Intermediates != nil {
		verifyOpts.Intermediates = opts.Intermediates.toStdCertPool()
	}

	chains, err := cert.Verify(verifyOpts)
	if err == nil && len(chains) > 0 {
		return nil
	}

	// Standard verification failed; try gmsm/smx509 for SM2 certificates.
	if IsSM2PublicKey(cert.PublicKey) {
		return verifySM2(cert, opts)
	}

	if err != nil {
		return err
	}
	return errNoCertChain
}

// verifySM2 verifies an SM2 certificate using gmsm/smx509.
func verifySM2(cert *x509.Certificate, opts VerifyOptions) error {
	smCert, err := smx509.ParseCertificate(cert.Raw)
	if err != nil {
		return fmt.Errorf("smx509: parse SM2 cert: %w", err)
	}

	// gmsm's ExtKeyUsage is a distinct int-backed type from stdlib's; convert
	// element-wise (constant values are identical).
	var smKeyUsages []smx509.ExtKeyUsage
	for _, ku := range opts.KeyUsages {
		smKeyUsages = append(smKeyUsages, smx509.ExtKeyUsage(ku))
	}

	smOpts := smx509.VerifyOptions{
		DNSName:   opts.DNSName,
		KeyUsages: smKeyUsages,
	}

	if opts.Roots != nil && opts.Roots.Len() > 0 {
		smRoots := smx509.NewCertPool()
		for _, raw := range opts.Roots.RawDER() {
			if smRC, parseErr := smx509.ParseCertificate(raw); parseErr == nil {
				smRoots.AddCert(smRC)
			}
		}
		smOpts.Roots = smRoots
	}

	chains, err := smCert.Verify(smOpts)
	if err != nil {
		return err
	}
	if len(chains) == 0 {
		return errNoCertChain
	}
	return nil
}

// VerifyDualCerts verifies a TLCP dual certificate pair (sign + encrypt).
// It checks pairing constraints: same issuer, same subject, correct key usage.
// Chain verification is the caller's responsibility (each cert verified against
// its own root pool separately).
func VerifyDualCerts(signCert, encCert *x509.Certificate) error {
	if signCert == nil || encCert == nil {
		return errMissingEncryptCert
	}

	// Same issuer check
	if !bytes.Equal(signCert.RawIssuer, encCert.RawIssuer) {
		return errMismatchedCA
	}

	// Same subject check
	if !bytes.Equal(signCert.RawSubject, encCert.RawSubject) {
		return errors.New("smx509: sign and encrypt certificates must have same subject")
	}

	// Sign cert key usage
	if signCert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("%w: sign cert missing digitalSignature", errInvalidKeyUsage)
	}

	// Encrypt cert key usage
	if encCert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 &&
		encCert.KeyUsage&x509.KeyUsageDataEncipherment == 0 {
		return fmt.Errorf("%w: encrypt cert missing keyEncipherment or dataEncipherment", errInvalidKeyUsage)
	}

	return nil
}

// toStdCertPool converts a CertPool to a standard x509.CertPool.
func (p *CertPool) toStdCertPool() *x509.CertPool {
	if p == nil {
		return nil
	}
	pool := x509.NewCertPool()
	for _, cert := range p.Certificates() {
		pool.AddCert(cert)
	}
	return pool
}

// contains checks if the pool contains a certificate with matching Raw bytes.
func (p *CertPool) contains(cert *x509.Certificate) bool {
	if p == nil {
		return false
	}
	for _, raw := range p.RawDER() {
		if bytes.Equal(raw, cert.Raw) {
			return true
		}
	}
	return false
}
