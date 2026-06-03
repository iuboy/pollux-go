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
	if len(suites) != 4 {
		t.Fatalf("expected 4 national suites, got %d", len(suites))
	}
	for _, s := range suites {
		if !IsNationalCipherSuite(s) {
			t.Errorf("suite 0x%04X not recognized as national", s)
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
	if len(suites) != 8 {
		t.Fatalf("expected 8 hybrid suites, got %d", len(suites))
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
