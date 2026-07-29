package smx509

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"reflect"

	smx509pkg "github.com/emmansun/gmsm/smx509"
)

// CreateRevocationList creates a CRL signed by the issuer.
// If the issuer key is SM2, gmsm/smx509 is used for SM2+SM3 signing.
// template, issuer, and signer MUST all be non-nil.
func CreateRevocationList(template *x509.RevocationList, issuer *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	if template == nil {
		return nil, errors.New("smx509: nil CRL template")
	}
	if issuer == nil {
		return nil, errors.New("smx509: nil issuer certificate")
	}
	if signer == nil {
		return nil, errors.New("smx509: nil signer")
	}
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
// *smx509.RevocationList.
//
// When the template already carries a DER encoding (tpl.Raw non-empty), it is
// parsed directly by smx509 — a lossless round-trip that mirrors
// toSMX509Certificate. This matters when re-signing an already-parsed CRL (e.g.
// rotating the signing key) where reflection-based field copy could drop or
// mis-convert nested types.
//
// A fresh template (Raw empty) cannot round-trip, so it falls back to a
// reflection field copy (copyCertFields): shared fields carry over, smx509-only
// fields stay zero, and enum-typed fields (SignatureAlgorithm) and entry slices
// (RevokedCertificateEntries) convert element-wise.
func toSMX509RevocationList(tpl *x509.RevocationList) (*smx509pkg.RevocationList, error) {
	if tpl == nil {
		return nil, nil
	}
	if len(tpl.Raw) > 0 {
		// Lossless DER round-trip — preferred when the template was parsed from
		// DER. Avoids any field-type drift between the stdlib and gmsm forks.
		return smx509pkg.ParseRevocationList(tpl.Raw)
	}
	sm := &smx509pkg.RevocationList{}
	copyCertFields(reflect.ValueOf(tpl).Elem(), reflect.ValueOf(sm).Elem())
	return sm, nil
}
