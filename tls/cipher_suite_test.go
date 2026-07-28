package tls

import (
	"crypto/tls"
	"testing"
)

func TestGetCipherSuitesNational(t *testing.T) {
	suites, err := GetCipherSuites(CryptoModeNational)
	if err != nil {
		t.Fatalf("GetCipherSuites(national): %v", err)
	}
	// The default national selection is GCM + ECDHE (forward secrecy) only;
	// CBC and static ECC suites are excluded (see LegacyNationalCipherSuites).
	if len(suites) != 1 {
		t.Fatalf("expected 1 secure national suite (GCM+ECDHE), got %d", len(suites))
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
	suites, err := GetCipherSuites(CryptoModeInternational)
	if err != nil {
		t.Fatalf("GetCipherSuites(international): %v", err)
	}
	if len(suites) != 4 {
		t.Fatalf("expected 4 international suites, got %d", len(suites))
	}
}

func TestGetCipherSuitesHybrid(t *testing.T) {
	suites, err := GetCipherSuites(CryptoModeHybrid)
	if err != nil {
		t.Fatalf("GetCipherSuites(hybrid): %v", err)
	}
	// 4 international + 1 secure national (GCM+ECDHE) = 5.
	if len(suites) != 5 {
		t.Fatalf("expected 5 hybrid suites, got %d", len(suites))
	}
}

func TestGetCipherSuitesInvalid(t *testing.T) {
	_, err := GetCipherSuites(CryptoMode("bogus"))
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
