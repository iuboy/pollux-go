package tls

import (
	"crypto/tls"
	"testing"
)

func TestGetCipherSuitesNational(t *testing.T) {
	suites, err := CipherSuites(CryptoModeNational)
	if err != nil {
		t.Fatalf("CipherSuites(national): %v", err)
	}
	// The default national selection is GCM/CCM with forward secrecy only:
	// the TLS 1.2 ECDHE_SM2_WITH_SM4_GCM_SM3 suite plus the RFC 8998 TLS 1.3
	// GM suites (TLS_SM4_GCM_SM3, TLS_SM4_CCM_SM3) — TLS 1.3 mandates
	// ephemeral key exchange so the 1.3 suites meet the same PFS+AEAD bar.
	// CBC and static ECC suites are excluded (see LegacyNationalCipherSuites).
	if len(suites) != 3 {
		t.Fatalf("expected 3 secure national suites (GCM+ECDHE + RFC 8998 TLS 1.3), got %d", len(suites))
	}
	if suites[0] != ECDHE_SM2_WITH_SM4_GCM_SM3 {
		t.Errorf("expected ECDHE_SM2_WITH_SM4_GCM_SM3, got 0x%04X", suites[0])
	}
	for _, s := range suites {
		if !IsNationalCipherSuite(s) {
			t.Errorf("suite 0x%04X not recognized as national", s)
		}
	}
}

func TestLegacyNationalCipherSuites(t *testing.T) {
	suites := LegacyNationalCipherSuites()
	// Legacy list includes CBC and static ECC suites (4 total).
	if len(suites) != 4 {
		t.Fatalf("expected 4 legacy national suites, got %d", len(suites))
	}
	for _, s := range suites {
		if !IsNationalCipherSuite(s) {
			t.Errorf("legacy suite 0x%04X not recognized as national", s)
		}
	}
}

func TestGetCipherSuitesInternational(t *testing.T) {
	suites, err := CipherSuites(CryptoModeInternational)
	if err != nil {
		t.Fatalf("CipherSuites(international): %v", err)
	}
	if len(suites) != 4 {
		t.Fatalf("expected 4 international suites, got %d", len(suites))
	}
}

func TestGetCipherSuitesHybrid(t *testing.T) {
	suites, err := CipherSuites(CryptoModeHybrid)
	if err != nil {
		t.Fatalf("CipherSuites(hybrid): %v", err)
	}
	// 4 international + 3 secure national (ECDHE GCM + RFC 8998 TLS 1.3 GM) = 7.
	if len(suites) != 7 {
		t.Fatalf("expected 7 hybrid suites, got %d", len(suites))
	}
}

func TestGetCipherSuitesInvalid(t *testing.T) {
	_, err := CipherSuites(CryptoMode("bogus"))
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestNationalCipherSuites(t *testing.T) {
	suites := NationalCipherSuites()
	if len(suites) == 0 {
		t.Fatal("NationalCipherSuites returned empty")
	}
}

func TestCipherSuiteName(t *testing.T) {
	tests := []struct {
		id   uint16
		want string
	}{
		{ECDHE_SM2_WITH_SM4_GCM_SM3, "ECDHE_SM2_WITH_SM4_GCM_SM3"},
		{ECDHE_SM2_WITH_SM4_CBC_SM3, "ECDHE_SM2_WITH_SM4_CBC_SM3"},
		{ECC_SM2_WITH_SM4_GCM_SM3, "ECC_SM2_WITH_SM4_GCM_SM3"},
		{ECC_SM2_WITH_SM4_CBC_SM3, "ECC_SM2_WITH_SM4_CBC_SM3"},
		{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	}
	for _, tt := range tests {
		got := CipherSuiteName(tt.id)
		if got != tt.want {
			t.Errorf("CipherSuiteName(0x%04X) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestIsNationalCipherSuite(t *testing.T) {
	if IsNationalCipherSuite(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) {
		t.Error("standard suite should not be national")
	}
	if !IsNationalCipherSuite(ECDHE_SM2_WITH_SM4_GCM_SM3) {
		t.Error("ECDHE_SM2_WITH_SM4_GCM_SM3 should be national")
	}
}
