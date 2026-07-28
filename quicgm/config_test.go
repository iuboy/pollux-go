package quicgm

import (
	"testing"
)

// TestTls13ClientConfig_EarlyDataRequiresPSK is the regression guard for the
// EarlyData-without-PSK misconfiguration: 0-RTT keys the early secret from the
// resumption PSK, so offering EarlyData without a PSK is meaningless and leads
// to an undefined handshake. Fail closed with a clear error.
func TestTls13ClientConfig_EarlyDataRequiresPSK(t *testing.T) {
	// EarlyData=true but no ResumptionPSK → must error.
	cfg := ClientConfig{
		ServerName:    "example.com",
		EarlyData:     true,
		ResumptionPSK: nil,
	}
	if _, err := cfg.tls13ClientConfig(); err == nil {
		t.Fatal("tls13ClientConfig accepted EarlyData with nil ResumptionPSK (regression)")
	}

	// Same with an empty (non-nil) PSK.
	cfgEmpty := ClientConfig{
		ServerName:    "example.com",
		EarlyData:     true,
		ResumptionPSK: []byte{},
	}
	if _, err := cfgEmpty.tls13ClientConfig(); err == nil {
		t.Fatal("tls13ClientConfig accepted EarlyData with empty ResumptionPSK (regression)")
	}

	// EarlyData=false (or no EarlyData) without a PSK is fine — full handshake.
	cfgFull := ClientConfig{ServerName: "example.com"}
	if _, err := cfgFull.tls13ClientConfig(); err != nil {
		t.Fatalf("full-handshake config (no EarlyData, no PSK) should be valid: %v", err)
	}

	// EarlyData=true WITH a PSK is fine.
	cfgPSK := ClientConfig{
		ServerName:    "example.com",
		EarlyData:     true,
		ResumptionPSK: []byte("a-resumption-psk-of-some-length"),
	}
	if _, err := cfgPSK.tls13ClientConfig(); err != nil {
		t.Fatalf("EarlyData with a PSK should be valid: %v", err)
	}
}
