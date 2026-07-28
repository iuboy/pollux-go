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
	errNilPublicKey   = errors.New("smx509: public key is nil")
	errNilTemplate    = errors.New("smx509: template is nil")
	errNilCertificate = errors.New("smx509: certificate is nil")
)

// CreateSubjectKeyIdentifierExtension builds a SubjectKeyIdentifier extension
// (RFC 5280 §4.2.1.2) from a key identifier. SKI is non-critical.
// Returns an empty Extension if keyID is empty.
func CreateSubjectKeyIdentifierExtension(keyID []byte) pkix.Extension {
	if len(keyID) == 0 {
		return pkix.Extension{}
	}
	value, _ := asn1.Marshal(keyID)
	return pkix.Extension{
		Id:       OIDSubjectKeyIdentifier,
		Critical: false,
		Value:    value,
	}
}

// GenerateSubjectKeyIdentifier computes a SubjectKeyIdentifier from a public key
// using the RFC 5280 §4.2.1.2 recommended method (SHA-1 over the PKIX-encoded
// public key). SHA-1 is safe for key-identifier binding (no preimage concern).
// SM2-aware: MarshalPKIXPublicKey handles both SM2 and standard keys.
func GenerateSubjectKeyIdentifier(pubKey crypto.PublicKey) ([]byte, error) {
	pubKeyBytes, err := MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("smx509: encode public key: %w", err)
	}
	hash := crypto.SHA1.New()
	hash.Write(pubKeyBytes)
	return hash.Sum(nil), nil
}

// CreateAuthorityKeyIdentifierExtension builds an AuthorityKeyIdentifier
// extension (RFC 5280 §4.2.1.1) from a key identifier. AKI is non-critical.
// Returns an empty Extension if keyID is empty.
func CreateAuthorityKeyIdentifierExtension(keyID []byte) pkix.Extension {
	if len(keyID) == 0 {
		return pkix.Extension{}
	}
	value, _ := asn1.Marshal(keyID)
	return pkix.Extension{
		Id:       OIDAuthorityKeyIdentifier,
		Critical: false,
		Value:    value,
	}
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

	extensions := make([]pkix.Extension, 0, 2)

	if len(subjectKeyID) == 0 && template.PublicKey != nil {
		ski, err := GenerateSubjectKeyIdentifier(template.PublicKey)
		if err != nil {
			return fmt.Errorf("smx509: generate SKI: %w", err)
		}
		subjectKeyID = ski
	}
	if len(subjectKeyID) > 0 {
		extensions = append(extensions, CreateSubjectKeyIdentifierExtension(subjectKeyID))
	}

	if len(authorityKeyID) == 0 && issuerPubKey != nil {
		aki, err := GenerateAuthorityKeyIdentifier(issuerPubKey)
		if err != nil {
			return fmt.Errorf("smx509: generate AKI: %w", err)
		}
		authorityKeyID = aki
	}
	if len(authorityKeyID) > 0 {
		extensions = append(extensions, CreateAuthorityKeyIdentifierExtension(authorityKeyID))
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
// scanning Extensions. Returns nil if absent or cert is nil.
func GetAuthorityKeyIdentifier(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}
	if len(cert.AuthorityKeyId) > 0 {
		return cert.AuthorityKeyId
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDAuthorityKeyIdentifier) {
			var keyID []byte
			if _, err := asn1.Unmarshal(ext.Value, &keyID); err == nil {
				return keyID
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
			issues = append(issues, "AuthorityKeyIdentifier shorter than 16 bytes")
		}
	}

	return len(issues) == 0, issues
}
