package smx509

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
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
//
// Returns an error (rather than a zero-value pkix.Extension) when reason is
// outside the RFC 5280 §5.3.1 valid range (0-10 excluding 7) or ASN.1 marshaling
// fails. This makes an out-of-range reason an explicit, checkable failure
// instead of a sentinel the caller must remember to test for — preventing a
// malformed (empty-Value) extension from being silently injected into a CRL.
func CreateCRLReasonExtension(reason CRLReason) (pkix.Extension, error) {
	// Validate reason range (RFC 5280 §5.3.1: valid values are 0-10 excluding 7).
	if reason < 0 || reason > 10 || reason == 7 {
		return pkix.Extension{}, fmt.Errorf("smx509: invalid CRL reason %d (RFC 5280 §5.3.1)", reason)
	}
	// CRLReason is an ENUMERATED type per RFC 5280 §5.3.1 (tag 0x0A, not
	// INTEGER tag 0x02). Use asn1.Enumerated for spec-conformant encoding.
	value, err := asn1.Marshal(asn1.Enumerated(reason))
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("smx509: marshal CRL reason: %w", err)
	}
	return pkix.Extension{
		Id:       OIDCRLReason,
		Critical: false,
		Value:    value,
	}, nil
}

// CreateInvalidityDateExtension builds an InvalidityDate extension
// (RFC 5280 §5.3.2) encoding the date the certificate is considered invalid.
// The extension is non-critical.
//
// Returns an error on ASN.1 marshaling failure (effectively unreachable for a
// valid time.Time), making the failure explicit rather than a sentinel
// zero-value extension the caller must remember to skip.
func CreateInvalidityDateExtension(date time.Time) (pkix.Extension, error) {
	// InvalidityDate is a GeneralizedTime per RFC 5280 §5.3.2 (tag 0x18).
	// Marshal the time.Time directly with "generalized" params so the tag is
	// correct; marshaling a string would produce UTF8String (tag 0x0C).
	value, err := asn1.MarshalWithParams(date.UTC(), "generalized")
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("smx509: marshal invalidity date: %w", err)
	}
	return pkix.Extension{
		Id:       OIDInvalidityDate,
		Critical: false,
		Value:    value,
	}, nil
}

// ParseCRLReason extracts the CRLReason from a CRL entry's extensions.
// Returns (ReasonUnspecified, false) if the extension is absent or the value
// is outside the RFC 5280 §5.3.1 valid range (0-10, excluding 7).
func ParseCRLReason(extensions []pkix.Extension) (CRLReason, bool) {
	for _, ext := range extensions {
		if ext.Id.Equal(OIDCRLReason) {
			var reason asn1.Enumerated
			if _, err := asn1.Unmarshal(ext.Value, &reason); err == nil {
				r := CRLReason(reason)
				if r >= 0 && r <= 10 && r != 7 {
					return r, true
				}
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
			// Decode directly into time.Time — Go's asn1 accepts both UTCTime
			// and GeneralizedTime for time.Time, matching standard tools.
			var date time.Time
			if _, err := asn1.Unmarshal(ext.Value, &date); err == nil {
				return date, true
			}
		}
	}
	return time.Time{}, false
}
