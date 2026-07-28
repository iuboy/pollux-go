package smx509

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"
)

// CRLReason is the CRLReason enumerated type from RFC 5280 §5.3.1.
// Values are fixed explicit constants: value 7 is reserved by RFC 5280
// and must not be used, so iota-style implicit numbering is avoided.
type CRLReason int

const (
	ReasonUnspecified          CRLReason = 0 // unspecified
	ReasonKeyCompromise        CRLReason = 1 // keyCompromise
	ReasonCACompromise         CRLReason = 2 // cACompromise
	ReasonAffiliationChanged   CRLReason = 3 // affiliationChanged
	ReasonSuperseded           CRLReason = 4 // superseded
	ReasonCessationOfOperation CRLReason = 5 // cessationOfOperation
	ReasonCertificateHold      CRLReason = 6 // certificateHold
	// Value 7 is unused in RFC 5280 §5.3.1 and must not be defined.
	ReasonRemoveFromCRL      CRLReason = 8  // removeFromCRL
	ReasonPrivilegeWithdrawn CRLReason = 9  // privilegeWithdrawn
	ReasonAACompromise       CRLReason = 10 // aACompromise
)

// String returns the RFC 5280 §5.3.1 name (camelCase).
func (r CRLReason) String() string {
	switch r {
	case ReasonUnspecified:
		return "unspecified"
	case ReasonKeyCompromise:
		return "keyCompromise"
	case ReasonCACompromise:
		return "cACompromise"
	case ReasonAffiliationChanged:
		return "affiliationChanged"
	case ReasonSuperseded:
		return "superseded"
	case ReasonCessationOfOperation:
		return "cessationOfOperation"
	case ReasonCertificateHold:
		return "certificateHold"
	case ReasonRemoveFromCRL:
		return "removeFromCRL"
	case ReasonPrivilegeWithdrawn:
		return "privilegeWithdrawn"
	case ReasonAACompromise:
		return "aACompromise"
	default:
		return "unknown"
	}
}

// CRL extension OIDs (RFC 5280 §5.3).
var (
	OIDCRLReason      = asn1.ObjectIdentifier{2, 5, 29, 21}
	OIDInvalidityDate = asn1.ObjectIdentifier{2, 5, 29, 24}
)

// CreateCRLReasonExtension builds a CRLReason extension (RFC 5280 §5.3.1).
// The extension is non-critical.
func CreateCRLReasonExtension(reason CRLReason) pkix.Extension {
	value, _ := asn1.Marshal(int(reason))
	return pkix.Extension{
		Id:       OIDCRLReason,
		Critical: false,
		Value:    value,
	}
}

// CreateInvalidityDateExtension builds an InvalidityDate extension
// (RFC 5280 §5.3.2) encoding the date the certificate is considered invalid.
// The extension is non-critical.
func CreateInvalidityDateExtension(date time.Time) pkix.Extension {
	generalizedTime := date.UTC().Format("20060102150405Z")
	value, _ := asn1.Marshal(generalizedTime)
	return pkix.Extension{
		Id:       OIDInvalidityDate,
		Critical: false,
		Value:    value,
	}
}

// ParseCRLReason extracts the CRLReason from a CRL entry's extensions.
// Returns (ReasonUnspecified, false) if the extension is absent.
func ParseCRLReason(extensions []pkix.Extension) (CRLReason, bool) {
	for _, ext := range extensions {
		if ext.Id.Equal(OIDCRLReason) {
			var reason int
			if _, err := asn1.Unmarshal(ext.Value, &reason); err == nil {
				return CRLReason(reason), true
			}
		}
	}
	return ReasonUnspecified, false
}

// ParseInvalidityDate extracts the InvalidityDate from a CRL entry's extensions.
// Returns (zero time, false) if the extension is absent or unparseable.
func ParseInvalidityDate(extensions []pkix.Extension) (time.Time, bool) {
	for _, ext := range extensions {
		if ext.Id.Equal(OIDInvalidityDate) {
			var dateStr string
			if _, err := asn1.Unmarshal(ext.Value, &dateStr); err == nil {
				if date, err := time.Parse("20060102150405Z", dateStr); err == nil {
					return date, true
				}
			}
		}
	}
	return time.Time{}, false
}
