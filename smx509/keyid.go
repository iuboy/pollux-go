package smx509

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// RFC 5280 certificate extension OIDs for key identifiers.
var (
	OIDSubjectKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 14}
	OIDAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
)

var (
	errNilPublicKey = errors.New("smx509: public key is nil")
	errNilTemplate  = errors.New("smx509: template is nil")
)

// CreateSubjectKeyIdentifierExtension builds a SubjectKeyIdentifier extension
// (RFC 5280 §4.2.1.2) from a key identifier. SKI is non-critical.
//
// An empty keyID returns a zero-value pkix.Extension (Id == nil) with a nil
// error, signalling "no extension to add" — callers should check `ext.Id !=
// nil` before appending. An ASN.1 marshal failure (effectively unreachable for
// a []byte) returns an error. This matches the (Extension, error) shape of the
// other Create*Extension helpers, keeping the four functions consistent.
func CreateSubjectKeyIdentifierExtension(keyID []byte) (pkix.Extension, error) {
	if len(keyID) == 0 {
		return pkix.Extension{}, nil
	}
	value, err := asn1.Marshal(keyID)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("smx509: marshal SKI: %w", err)
	}
	return pkix.Extension{
		Id:       OIDSubjectKeyIdentifier,
		Critical: false,
		Value:    value,
	}, nil
}

// GenerateSubjectKeyIdentifier computes a SubjectKeyIdentifier from a public key
// using the RFC 5280 §4.2.1.2 recommended method (SHA-1 over the PKIX-encoded
// public key). SHA-1 is safe for key-identifier binding (no preimage concern).
// SM2-aware: MarshalPKIXPublicKey handles both SM2 and standard keys.
func GenerateSubjectKeyIdentifier(pubKey crypto.PublicKey) ([]byte, error) {
	if pubKey == nil {
		return nil, errNilPublicKey
	}
	pubKeyBytes, err := MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("smx509: encode public key: %w", err)
	}
	hash := crypto.SHA1.New()
	hash.Write(pubKeyBytes)
	return hash.Sum(nil), nil
}

// authorityKeyIdentifier is the RFC 5280 §4.2.1.1 SEQUENCE structure.
// Tags mirror crypto/x509's internal representation.
type authorityKeyIdentifier struct {
	KeyIdentifier []byte `asn1:"optional,tag:0"`
}

// CreateAuthorityKeyIdentifierExtension builds an AuthorityKeyIdentifier
// extension (RFC 5280 §4.2.1.1) from a key identifier. AKI is non-critical.
//
// As with CreateSubjectKeyIdentifierExtension, an empty keyID returns a
// zero-value extension with a nil error ("nothing to add"); a marshal failure
// returns an error.
func CreateAuthorityKeyIdentifierExtension(keyID []byte) (pkix.Extension, error) {
	if len(keyID) == 0 {
		return pkix.Extension{}, nil
	}
	value, err := asn1.Marshal(authorityKeyIdentifier{KeyIdentifier: keyID})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("smx509: marshal AKI: %w", err)
	}
	return pkix.Extension{
		Id:       OIDAuthorityKeyIdentifier,
		Critical: false,
		Value:    value,
	}, nil
}

// GenerateAuthorityKeyIdentifier computes an AuthorityKeyIdentifier from an
// issuer public key using the SHA-1 method (consistent with SKI).
// SM2-aware: MarshalPKIXPublicKey handles both SM2 and standard keys.
func GenerateAuthorityKeyIdentifier(issuerPubKey crypto.PublicKey) ([]byte, error) {
	if issuerPubKey == nil {
		return nil, errNilPublicKey
	}
	pubKeyBytes, err := MarshalPKIXPublicKey(issuerPubKey)
	if err != nil {
		return nil, fmt.Errorf("smx509: encode issuer public key: %w", err)
	}
	hash := crypto.SHA1.New()
	hash.Write(pubKeyBytes)
	return hash.Sum(nil), nil
}

// AddRFC5280KeyIdentifiers attaches SKI and AKI extensions to a certificate
// template's ExtraExtensions. If subjectKeyID/authorityKeyID are empty, they
// are auto-generated from template.PublicKey / issuerPubKey respectively.
func AddRFC5280KeyIdentifiers(
	template *x509.Certificate,
	subjectKeyID []byte,
	authorityKeyID []byte,
	issuerPubKey crypto.PublicKey,
) error {
	if template == nil {
		return errNilTemplate
	}

	// RFC 5280 §4.2: an extension MUST NOT appear more than once in a
	// certificate. Scan both ExtraExtensions (caller-set) and Extensions
	// (populated by a prior CreateCertificate / previous AddRFC5280 call) and
	// skip any identifier already present, so re-calling this helper on a
	// template that already carries SKI/AKI does not inject duplicates.
	hasExt := func(oid asn1.ObjectIdentifier) bool {
		for _, ext := range template.ExtraExtensions {
			if ext.Id.Equal(oid) {
				return true
			}
		}
		for _, ext := range template.Extensions {
			if ext.Id.Equal(oid) {
				return true
			}
		}
		return false
	}

	extensions := make([]pkix.Extension, 0, 2)

	if len(subjectKeyID) == 0 && template.PublicKey != nil {
		ski, err := GenerateSubjectKeyIdentifier(template.PublicKey)
		if err != nil {
			return fmt.Errorf("smx509: generate SKI: %w", err)
		}
		subjectKeyID = ski
	}
	if len(subjectKeyID) > 0 && !hasExt(OIDSubjectKeyIdentifier) {
		ext, err := CreateSubjectKeyIdentifierExtension(subjectKeyID)
		if err != nil {
			return fmt.Errorf("smx509: build SKI extension: %w", err)
		}
		if ext.Id != nil { // non-nil Id => a real extension was produced
			extensions = append(extensions, ext)
		}
	}

	if len(authorityKeyID) == 0 && issuerPubKey != nil {
		aki, err := GenerateAuthorityKeyIdentifier(issuerPubKey)
		if err != nil {
			return fmt.Errorf("smx509: generate AKI: %w", err)
		}
		authorityKeyID = aki
	}
	if len(authorityKeyID) > 0 && !hasExt(OIDAuthorityKeyIdentifier) {
		ext, err := CreateAuthorityKeyIdentifierExtension(authorityKeyID)
		if err != nil {
			return fmt.Errorf("smx509: build AKI extension: %w", err)
		}
		if ext.Id != nil {
			extensions = append(extensions, ext)
		}
	}

	template.ExtraExtensions = append(template.ExtraExtensions, extensions...)
	return nil
}

// GetSubjectKeyIdentifier extracts the SubjectKeyIdentifier from a certificate.
// Prefers the pre-parsed cert.SubjectKeyId; falls back to scanning Extensions.
// Returns nil if absent or cert is nil.
func GetSubjectKeyIdentifier(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}
	if len(cert.SubjectKeyId) > 0 {
		return cert.SubjectKeyId
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDSubjectKeyIdentifier) {
			var keyID []byte
			if _, err := asn1.Unmarshal(ext.Value, &keyID); err == nil {
				return keyID
			}
		}
	}
	return nil
}

// GetAuthorityKeyIdentifier extracts the AuthorityKeyIdentifier from a
// certificate. Prefers the pre-parsed cert.AuthorityKeyId; falls back to
// scanning Extensions and parsing the RFC 5280 SEQUENCE wrapper.
// Returns nil if absent or cert is nil.
func GetAuthorityKeyIdentifier(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}
	if len(cert.AuthorityKeyId) > 0 {
		return cert.AuthorityKeyId
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDAuthorityKeyIdentifier) {
			var aki authorityKeyIdentifier
			if _, err := asn1.Unmarshal(ext.Value, &aki); err == nil {
				return aki.KeyIdentifier
			}
		}
	}
	return nil
}

// ValidateKeyIdentifiers checks that a certificate's SKI/AKI conform to
// RFC 5280 expectations. Returns (ok, issues) where issues lists human-readable
// problem descriptions. Self-signed certificates (Subject == Issuer by DER) are
// not required to have an AKI.
func ValidateKeyIdentifiers(cert *x509.Certificate) (bool, []string) {
	if cert == nil {
		return false, []string{"certificate is nil"}
	}
	var issues []string

	ski := GetSubjectKeyIdentifier(cert)
	if len(ski) == 0 {
		issues = append(issues, "missing SubjectKeyIdentifier extension")
	} else if len(ski) < 16 {
		// 16 bytes is a PACKAGE POLICY threshold, not an RFC 5280 requirement:
		// the RFC only mandates a non-empty key identifier (§4.2.1.2) and
		// recommends — does not require — the SHA-1 method (20 bytes). The
		// floor here flags identifiers below 128 bits of collision resistance;
		// treat the reported issue as advisory, not a standards violation.
		issues = append(issues, "SubjectKeyIdentifier shorter than 16 bytes")
	}

	// Self-signed detection: compare the canonical DER-encoded Subject and
	// Issuer. Comparing only the CommonName field is unsound — two different
	// CAs may share a CN, and a Subject may be distinguished by non-CN RDNs
	// (O, OU, etc.). RawSubject/RawIssuer are the canonical BER forms.
	isSelfSigned := bytes.Equal(cert.RawSubject, cert.RawIssuer)
	if !isSelfSigned {
		aki := GetAuthorityKeyIdentifier(cert)
		if len(aki) == 0 {
			issues = append(issues, "non-self-signed certificate missing AuthorityKeyIdentifier extension")
		} else if len(aki) < 16 {
			// Same package-policy threshold as the SKI check above: RFC 5280
			// §4.2.1.1 only requires the keyIdentifier field to be present
			// when the extension is used; 16 bytes is this package's
			// 128-bit floor, advisory only.
			issues = append(issues, "AuthorityKeyIdentifier shorter than 16 bytes")
		}
	}

	return len(issues) == 0, issues
}
