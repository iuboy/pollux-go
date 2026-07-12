package smx509

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"reflect"

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
		// directly assignable to *smx509.RevocationList. Convert via reflection
		// field copy (copyCertFields). A fresh template (empty Raw) is the normal
		// case when creating a new CRL, so DER round-trip is not viable here.
		smTemplate, err := toSMX509RevocationList(template)
		if err != nil {
			return nil, err
		}
		return smx509pkg.CreateRevocationList(rand.Reader, smTemplate, smIssuer, signer)
	}
	return x509.CreateRevocationList(rand.Reader, template, issuer, signer)
}

// toSMX509RevocationList converts a stdlib *x509.RevocationList to
// *smx509.RevocationList via reflection-based field copy (see
// toSMX509Certificate). Fresh templates (Raw empty) are handled correctly:
// shared fields carry over, smx509-only fields stay zero. Enum-typed fields
// (SignatureAlgorithm) and entry slices (RevokedCertificateEntries) convert
// element-wise via copyCertFields.
func toSMX509RevocationList(tpl *x509.RevocationList) (*smx509pkg.RevocationList, error) {
	if tpl == nil {
		return nil, nil
	}
	sm := &smx509pkg.RevocationList{}
	copyCertFields(reflect.ValueOf(tpl).Elem(), reflect.ValueOf(sm).Elem())
	return sm, nil
}
