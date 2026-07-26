package smx509

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// RFC 5280 §4.2.2.1 Authority Information Access OIDs.
var (
	OIDAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	OIDAIAOCSP             = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	OIDAIACAIssuers        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

// aiaAccessDescription mirrors RFC 5280 AccessDescription.
type aiaAccessDescription struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue // GeneralName: URI [6] IMPLICIT IA5String
}

// CreateAuthorityInfoAccessExtension builds an Authority Information Access
// (AIA) extension (RFC 5280 §4.2.2.1) from OCSP responder URLs and CA
// Issuers URLs. The extension is non-critical. Returns a zero Extension if
// both lists are empty OR contain only empty strings — matching
// CreateCRLDistributionPointsExtension's behavior (which also returns a zero
// Extension when no non-empty URLs remain, after filtering empties).
//
// Note: crypto/x509.Certificate has direct fields only for CA Issuers
// (IssuingCertificateURL) — there is NO stdlib field for the OCSP access
// method. Use this helper to inject a complete AIA extension (covering OCSP)
// via ExtraExtensions.
func CreateAuthorityInfoAccessExtension(ocspURLs, caIssuerURLs []string) (pkix.Extension, error) {
	if len(ocspURLs) == 0 && len(caIssuerURLs) == 0 {
		return pkix.Extension{}, nil
	}

	var ads []aiaAccessDescription
	for _, u := range ocspURLs {
		if u == "" {
			continue
		}
		ads = append(ads, aiaAccessDescription{
			Method: OIDAIAOCSP,
			Location: asn1.RawValue{
				Class:      2, // context-specific
				Tag:        6, // uniformResourceIdentifier
				IsCompound: false,
				Bytes:      []byte(u),
			},
		})
	}
	for _, u := range caIssuerURLs {
		if u == "" {
			continue
		}
		ads = append(ads, aiaAccessDescription{
			Method: OIDAIACAIssuers,
			Location: asn1.RawValue{
				Class:      2,
				Tag:        6,
				IsCompound: false,
				Bytes:      []byte(u),
			},
		})
	}

	if len(ads) == 0 {
		return pkix.Extension{}, nil
	}

	value, err := asn1.Marshal(ads)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       OIDAuthorityInfoAccess,
		Critical: false,
		Value:    value,
	}, nil
}

// GetAuthorityInfoAccess extracts OCSP and CA Issuers URLs from a certificate's
// AIA extension.
//
// Only URI-form GeneralNames (context-specific class 2, tag 6) are accepted;
// other GeneralName forms (IP, DNS, etc.) are skipped silently per the AIA
// common-practice expectation that accessLocation is a URI.
//
// Return-value semantics — all three "no URLs" cases return (nil, nil) for
// caller-side simplicity (a nil slice tests false for "have an OCSP URL").
// To distinguish the cause, inspect the inputs directly:
//
//   - cert == nil: caller passed nothing; the function is a no-op.
//   - cert non-nil but no AIA extension present: the cert simply does not
//     carry AIA. Detect via cert.IsCA / a scan of cert.Extensions for
//     OIDAuthorityInfoAccess before calling.
//   - AIA extension present but ASN.1 parse failed: malformed extension.
//     This is rare and almost always indicates a corrupt or attacker-crafted
//     certificate; the function logs nothing but returns nil so the caller
//     degrades gracefully (treats the cert as having no AIA). If you need
//     to detect this case programmatically, pre-scan cert.Extensions for
//     the AIA OID and parse it yourself with a distinguishing error.
//
// Non-URI accessLocation entries (Class != 2 or Tag != 6) are silently
// skipped rather than surfaced — RFC 5280 §4.2.2.1 restricts AIA to URI
// form, so a non-URI entry is malformed and skipping it matches common
// CA-browser practice.
func GetAuthorityInfoAccess(cert *x509.Certificate) (ocspURLs, caIssuerURLs []string) {
	if cert == nil {
		return nil, nil
	}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(OIDAuthorityInfoAccess) {
			continue
		}
		var ads []aiaAccessDescription
		if _, err := asn1.Unmarshal(ext.Value, &ads); err != nil {
			// Malformed AIA extension — degrade to "no AIA" rather than
			// propagating the error. See the doc comment above for how to
			// detect this case if you need to.
			return nil, nil
		}
		for _, ad := range ads {
			// RFC 5280 §4.2.2.1: accessLocation is a GeneralName. AIA restricts
			// it to URI form (context-specific class 2, tag 6 = uniformResourceIdentifier).
			// Skip non-URI entries rather than emitting garbage bytes as a URL.
			if ad.Location.Class != 2 || ad.Location.Tag != 6 {
				continue
			}
			uri := string(ad.Location.Bytes)
			switch {
			case ad.Method.Equal(OIDAIAOCSP):
				ocspURLs = append(ocspURLs, uri)
			case ad.Method.Equal(OIDAIACAIssuers):
				caIssuerURLs = append(caIssuerURLs, uri)
			}
		}
		return ocspURLs, caIssuerURLs
	}
	return nil, nil
}

// CRLDistributionPoints OID (RFC 5280 §4.2.1.13).
var OIDCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}

// CreateCRLDistributionPointsExtension builds a CRL Distribution Points
// extension (RFC 5280 §4.2.1.13) from a list of CRL URLs (fullName
// GeneralNames, URI form). The extension is non-critical. Returns a zero
// Extension if fullNames is empty.
//
// In most cases callers can simply set template.CRLDistributionPoints and let
// crypto/x509 encode it; this helper is for cases where the extension must be
// injected directly into ExtraExtensions.
func CreateCRLDistributionPointsExtension(fullNames []string) (pkix.Extension, error) {
	if len(fullNames) == 0 {
		return pkix.Extension{}, nil
	}

	type distributionPointName struct {
		FullNames []asn1.RawValue `asn1:"tag:0,optional"`
	}
	type distributionPoint struct {
		DistributionPoint distributionPointName `asn1:"tag:0,optional"`
	}

	var dps []distributionPoint
	var names []asn1.RawValue
	for _, u := range fullNames {
		if u == "" {
			continue
		}
		names = append(names, asn1.RawValue{
			Class:      2, // context-specific
			Tag:        6, // uniformResourceIdentifier
			IsCompound: false,
			Bytes:      []byte(u),
		})
	}
	if len(names) == 0 {
		return pkix.Extension{}, errors.New("smx509: no non-empty CRL distribution point URLs")
	}
	dps = []distributionPoint{{DistributionPoint: distributionPointName{FullNames: names}}}

	value, err := asn1.Marshal(dps)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       OIDCRLDistributionPoints,
		Critical: false,
		Value:    value,
	}, nil
}
