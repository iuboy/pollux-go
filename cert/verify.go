package cert

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/ycq/pollux/internal/panicsafe"
	polluxSmx509 "github.com/ycq/pollux/smx509"
)

// VerifyOptions holds certificate verification parameters.
type VerifyOptions struct {
	DNSName       string
	Roots         *Pool
	Intermediates *Pool
	KeyUsages     []x509.ExtKeyUsage
	CurrentTime   time.Time
}

// VerifyCertificate verifies a certificate against the given options.
// It automatically selects standard x509 or SM2 verification.
func VerifyCertificate(cert *x509.Certificate, opts VerifyOptions) error {
	return panicsafe.Do(func() error {
		if cert == nil {
			return ErrUnsupportedCert
		}
		if opts.Roots == nil || opts.Roots.Len() == 0 {
			return ErrNoRoots
		}

		if IsSM2Certificate(cert) {
			return verifySM2(cert, opts)
		}
		return verifyStandard(cert, opts)
	})
}

func verifySM2(cert *x509.Certificate, opts VerifyOptions) error {
	smx509Opts := polluxSmx509.VerifyOptions{
		DNSName:       opts.DNSName,
		Roots:         opts.Roots.ToSMX509Pool(),
		Intermediates: intermediatesPool(opts),
	}
	return polluxSmx509.Verify(cert, smx509Opts)
}

func verifyStandard(cert *x509.Certificate, opts VerifyOptions) error {
	stdOpts := x509.VerifyOptions{
		DNSName:       opts.DNSName,
		Roots:         opts.Roots.ToStandardPool(),
		Intermediates: intermediatesStdPool(opts),
	}
	if len(opts.KeyUsages) > 0 {
		stdOpts.KeyUsages = opts.KeyUsages
	}
	if !opts.CurrentTime.IsZero() {
		stdOpts.CurrentTime = opts.CurrentTime
	}
	_, err := cert.Verify(stdOpts)
	return err
}

// VerifyDualCertificate verifies a TLCP dual certificate pair.
func VerifyDualCertificate(signCert, encCert *x509.Certificate, signRoots, encRoots *Pool) error {
	return panicsafe.Do(func() error {
		if signCert == nil || encCert == nil {
			return fmt.Errorf("cert: both sign and enc certificates are required")
		}

		signKeyUsage := signCert.KeyUsage
		if signKeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return fmt.Errorf("cert: sign certificate must have KeyUsageDigitalSignature")
		}

		encKeyUsage := encCert.KeyUsage
		if encKeyUsage&x509.KeyUsageKeyEncipherment == 0 && encKeyUsage&x509.KeyUsageDataEncipherment == 0 {
			return fmt.Errorf("cert: enc certificate must have KeyUsageKeyEncipherment or KeyUsageDataEncipherment")
		}

		if err := VerifyCertificate(signCert, VerifyOptions{Roots: signRoots}); err != nil {
			return fmt.Errorf("cert: sign certificate verification failed: %w", err)
		}
		if err := VerifyCertificate(encCert, VerifyOptions{Roots: encRoots}); err != nil {
			return fmt.Errorf("cert: enc certificate verification failed: %w", err)
		}
		return nil
	})
}

func intermediatesPool(opts VerifyOptions) *polluxSmx509.CertPool {
	if opts.Intermediates == nil {
		return nil
	}
	return opts.Intermediates.ToSMX509Pool()
}

func intermediatesStdPool(opts VerifyOptions) *x509.CertPool {
	if opts.Intermediates == nil {
		return nil
	}
	return opts.Intermediates.ToStandardPool()
}
