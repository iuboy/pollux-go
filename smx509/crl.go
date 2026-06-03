package smx509

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"

	smx509pkg "github.com/emmansun/gmsm/smx509"
)

// CreateRevocationList creates a CRL signed by the issuer.
// If the issuer key is SM2, gmsm/smx509 is used for SM2+SM3 signing.
func CreateRevocationList(template *x509.RevocationList, issuer *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	if IsSM2PublicKey(signer.Public()) {
		smIssuer := &smx509pkg.Certificate{}
		*smIssuer = smx509pkg.Certificate(*issuer)
		return smx509pkg.CreateRevocationList(rand.Reader, template, smIssuer, signer)
	}
	return x509.CreateRevocationList(rand.Reader, template, issuer, signer)
}
