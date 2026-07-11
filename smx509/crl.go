package smx509

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"

	smx509pkg "github.com/emmansun/gmsm/smx509"
)

// CreateRevocationList creates a CRL signed by the issuer.
// If the issuer key is SM2, gmsm/smx509 is used for SM2+SM3 signing.
func CreateRevocationList(template *x509.RevocationList, issuer *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	if IsSM2PublicKey(signer.Public()) {
		smIssuer, err := toSMX509Certificate(issuer)
		if err != nil {
			return nil, err
		}
		// gmsm v0.44 made smx509 a clean fork: *x509.RevocationList is no longer
		// directly assignable to *smx509.RevocationList. Round-trip via DER.
		if len(template.Raw) == 0 {
			return nil, errors.New("smx509: cannot convert revocation list with empty Raw field")
		}
		smTemplate, err := smx509pkg.ParseRevocationList(template.Raw)
		if err != nil {
			return nil, err
		}
		return smx509pkg.CreateRevocationList(rand.Reader, smTemplate, smIssuer, signer)
	}
	return x509.CreateRevocationList(rand.Reader, template, issuer, signer)
}
