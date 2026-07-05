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
		ext := CreateCRLReasonExtension(r)
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
	ext := CreateInvalidityDateExtension(date)
	got, ok := ParseInvalidityDate([]pkix.Extension{ext})
	if !ok {
		t.Fatal("ParseInvalidityDate: not found")
	}
	if !got.Equal(date) {
		t.Errorf("round-trip = %v, want %v", got, date)
	}
}

func TestParseInvalidityDate_Absent(t *testing.T) {
	_, ok := ParseInvalidityDate(nil)
	if ok {
		t.Error("expected ok=false for nil extensions")
	}
}
