package cert

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/iuboy/pollux-go/internal/panicsafe"
	polluxSmx509 "github.com/iuboy/pollux-go/smx509"
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
		if err := validateRootsAreCAs(opts.Roots); err != nil {
			return err
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
		KeyUsages:     opts.KeyUsages,
	}
	if err := polluxSmx509.Verify(cert, smx509Opts); err != nil {
		return fmt.Errorf("cert: SM2 certificate verification failed: %w", err)
	}

	// Manual ExtendedKeyUsage validation (gmsm/smx509 does not support this natively).
	if len(opts.KeyUsages) > 0 {
		if err := validateKeyUsages(cert, opts.KeyUsages); err != nil {
			return err
		}
	}

	// Manual time validation (gmsm/smx509 VerifyOptions does not support CurrentTime).
	currentTime := opts.CurrentTime
	if currentTime.IsZero() {
		currentTime = time.Now()
	}
	if currentTime.Before(cert.NotBefore) {
		return fmt.Errorf("cert: certificate not yet valid (current %s, not before %s)",
			currentTime.Format(time.RFC3339), cert.NotBefore.Format(time.RFC3339))
	}
	if currentTime.After(cert.NotAfter) {
		return fmt.Errorf("cert: certificate expired (current %s, not after %s)",
			currentTime.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}

	return nil
}

// validateRootsAreCAs rejects non-CA (leaf) certificates used as trust
// anchors. A trust root must be a CA; accepting a leaf as its own anchor would
// let any self-signed leaf bypass chain validation entirely.
func validateRootsAreCAs(roots *Pool) error {
	for _, c := range roots.Certificates() {
		if !c.IsCA {
			return fmt.Errorf("%w: %q is not a CA", ErrLeafAsRoot, c.Subject.String())
		}
	}
	return nil
}

// validateKeyUsages checks that the certificate has at least one of the required ExtendedKeyUsages.
func validateKeyUsages(cert *x509.Certificate, required []x509.ExtKeyUsage) error {
	if len(cert.ExtKeyUsage) == 0 {
		return nil // No EKU restriction on cert, accept any usage.
	}
	for _, req := range required {
		// RFC 5280 §4.2.1.12: ExtKeyUsageAny on the *requester* side means the
		// verifier accepts all usages, so the cert need not itself list Any.
		// Without this, required=[Any] with cert=[ServerAuth] was wrongly rejected.
		if req == x509.ExtKeyUsageAny {
			return nil
		}
		for _, present := range cert.ExtKeyUsage {
			if present == req || present == x509.ExtKeyUsageAny {
				return nil
			}
		}
	}
	return errors.New("cert: certificate does not have required ExtendedKeyUsage")
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

// VerifyDualCertificate verifies a TLCP dual certificate pair (signing +
// encryption). Each certificate is verified with its own [VerifyOptions], so
// callers can supply DNSName, Intermediates, KeyUsages, and CurrentTime per
// cert — the previous signature forwarded only Roots, silently dropping those
// checks (chain completeness via intermediates, hostname/EKU enforcement, and
// fixed-time verification).
//
// The TLCP-mandated basic KeyUsage bits are still enforced here regardless of
// opts.KeyUsages (ExtKeyUsage): sign cert must carry DigitalSignature; enc cert
// must carry KeyEncipherment, DataEncipherment, or KeyAgreement.
func VerifyDualCertificate(signCert, encCert *x509.Certificate, signOpts, encOpts VerifyOptions) error {
	return panicsafe.Do(func() error {
		if signCert == nil || encCert == nil {
			return errors.New("cert: both sign and enc certificates are required")
		}

		signKeyUsage := signCert.KeyUsage
		if signKeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return errors.New("cert: sign certificate must have KeyUsageDigitalSignature")
		}

		encKeyUsage := encCert.KeyUsage
		// TLCP encryption certs are used both for SM2 public-key encryption of the
		// PMS (KeyEncipherment / DataEncipherment) and, in ECDHE suites, for SM2
		// MQV key agreement (KeyAgreement). Accept any of the three usages so a
		// legitimate SM2 enc cert configured for ECDHE is not rejected.
		if encKeyUsage&x509.KeyUsageKeyEncipherment == 0 &&
			encKeyUsage&x509.KeyUsageDataEncipherment == 0 &&
			encKeyUsage&x509.KeyUsageKeyAgreement == 0 {
			return errors.New("cert: enc certificate must have KeyUsageKeyEncipherment, KeyUsageDataEncipherment, or KeyUsageKeyAgreement")
		}

		if err := VerifyCertificate(signCert, signOpts); err != nil {
			return fmt.Errorf("cert: sign certificate verification failed: %w", err)
		}
		if err := VerifyCertificate(encCert, encOpts); err != nil {
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
