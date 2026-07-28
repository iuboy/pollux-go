package tlcp

import (
	"crypto/x509"
	"strings"
	"testing"
)

// TestValidateDualCertPair_UsageErrors covers the wrapping paths in
// ValidateDualCertPair: a sign cert lacking DigitalSignature surfaces as a
// "sign cert" error, and an enc cert lacking key/data encipherment surfaces as
// an "encrypt cert" error — proving ValidateTLCPCertificate is invoked with the
// correct role and the cause is wrapped with a diagnosable prefix.
//
// (Single-cert branches are already covered in TestValidateTLCPCertificate;
// this targets the pair-level wrapping, which was untested.)
func TestValidateDualCertPair_UsageErrors(t *testing.T) {
	ca := selfSignCA(t, "usage-ca")
	serverAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	// A valid sign cert (digitalSignature) and enc cert (keyEncipherment),
	// both issued by the same CA so the issuer-consistency check passes.
	goodSign, _ := makeCert(t, certSpec{keyUsage: x509.KeyUsageDigitalSignature, eku: serverAuth, issuer: ca.cert, signer: ca.key})
	goodEnc, _ := makeCert(t, certSpec{keyUsage: x509.KeyUsageKeyEncipherment, eku: serverAuth, issuer: ca.cert, signer: ca.key})

	// Sign cert carrying only keyEncipherment (no digitalSignature).
	signNoSign, _ := makeCert(t, certSpec{keyUsage: x509.KeyUsageKeyEncipherment, eku: serverAuth, issuer: ca.cert, signer: ca.key})
	// Enc cert carrying only digitalSignature (no key/data encipherment).
	encNoEnc, _ := makeCert(t, certSpec{keyUsage: x509.KeyUsageDigitalSignature, eku: serverAuth, issuer: ca.cert, signer: ca.key})

	tests := []struct {
		name   string
		pair   *DualCertPair
		prefix string
	}{
		{"sign cert missing digitalSignature", &DualCertPair{SignCert: signNoSign, EncCert: goodEnc}, "sign cert"},
		{"enc cert missing key/data encipherment", &DualCertPair{SignCert: goodSign, EncCert: encNoEnc}, "encrypt cert"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDualCertPair(tt.pair)
			if err == nil {
				t.Fatal("expected a validation error, got nil")
			}
			if !strings.Contains(err.Error(), tt.prefix) {
				t.Errorf("error %q should mention %q", err.Error(), tt.prefix)
			}
		})
	}
}
