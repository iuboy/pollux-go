package smx509

import (
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestCRLReason_String(t *testing.T) {
	tests := []struct {
		r    CRLReason
		want string
	}{
		{ReasonUnspecified, "unspecified"},
		{ReasonKeyCompromise, "keyCompromise"},
		{ReasonCACompromise, "cACompromise"},
		{ReasonAffiliationChanged, "affiliationChanged"},
		{ReasonSuperseded, "superseded"},
		{ReasonCessationOfOperation, "cessationOfOperation"},
		{ReasonCertificateHold, "certificateHold"},
		{ReasonRemoveFromCRL, "removeFromCRL"},
		{ReasonPrivilegeWithdrawn, "privilegeWithdrawn"},
		{ReasonAACompromise, "aACompromise"},
		{CRLReason(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.r.String(); got != tt.want {
			t.Errorf("CRLReason(%d).String() = %q, want %q", tt.r, got, tt.want)
		}
	}
}

func TestCRLReason_RoundTrip(t *testing.T) {
	for _, r := range []CRLReason{
		ReasonUnspecified, ReasonKeyCompromise, ReasonCACompromise,
		ReasonAffiliationChanged, ReasonSuperseded, ReasonCessationOfOperation,
		ReasonCertificateHold, ReasonRemoveFromCRL, ReasonPrivilegeWithdrawn,
		ReasonAACompromise,
	} {
		ext, err := CreateCRLReasonExtension(r)
		if err != nil {
			t.Errorf("CreateCRLReasonExtension(%s): %v", r, err)
			continue
		}
		got, ok := ParseCRLReason([]pkix.Extension{ext})
		if !ok {
			t.Errorf("ParseCRLReason(%s): not found", r)
			continue
		}
		if got != r {
			t.Errorf("ParseCRLReason round-trip = %v, want %v", got, r)
		}
	}
}

func TestParseCRLReason_Absent(t *testing.T) {
	r, ok := ParseCRLReason(nil)
	if ok {
		t.Error("expected ok=false for nil extensions")
	}
	if r != ReasonUnspecified {
		t.Errorf("expected ReasonUnspecified, got %v", r)
	}
}

func TestInvalidityDate_RoundTrip(t *testing.T) {
	date := time.Date(2025, 3, 15, 10, 30, 0, 0, time.UTC)
	ext, err := CreateInvalidityDateExtension(date)
	if err != nil {
		t.Fatalf("CreateInvalidityDateExtension: %v", err)
	}
	got, ok := ParseInvalidityDate([]pkix.Extension{ext})
	if !ok {
		t.Fatal("ParseInvalidityDate: not found")
	}
	if !got.Equal(date) {
		t.Errorf("round-trip = %v, want %v", got, date)
	}
}

// TestCRLReason_OutOfRangeReturnsError is a regression test for the
// malformed-extension foot-gun: an out-of-range reason (or an ASN.1 marshal
// failure) previously returned an Extension carrying the CRLReason OID but an
// EMPTY Value — a fragment that, if appended to a CRL, produced invalid DER.
// With the (pkix.Extension, error) signature an out-of-range reason is now an
// explicit, checkable error instead of a sentinel zero-value extension.
func TestCRLReason_OutOfRangeReturnsError(t *testing.T) {
	for _, r := range []CRLReason{-1, 11, 7} { // below range, above range, reserved (7)
		ext, err := CreateCRLReasonExtension(r)
		if err == nil {
			t.Errorf("out-of-range reason %d: expected error, got ext Id=%v Value-len=%d", r, ext.Id, len(ext.Value))
		}
		if ext.Id != nil {
			t.Errorf("out-of-range reason %d: expected zero-value Extension on error, got Id=%v", r, ext.Id)
		}
	}
}

func TestParseInvalidityDate_Absent(t *testing.T) {
	_, ok := ParseInvalidityDate(nil)
	if ok {
		t.Error("expected ok=false for nil extensions")
	}
}
