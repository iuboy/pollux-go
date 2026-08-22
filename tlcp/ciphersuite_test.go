package tlcp

import (
	"testing"

	polluxtls "github.com/iuboy/pollux-go/tls"
)

// TestDefaultCipherSuites 验证默认套件仅含 GCM + ECDHE(前向保密)。
func TestDefaultCipherSuites(t *testing.T) {
	suites := DefaultCipherSuites()
	if len(suites) != 1 || suites[0] != SuiteECDHE_SM2_SM4_GCM_SM3 {
		t.Fatalf("default suites = %v, want only ECDHE_SM4_GCM_SM3", suites)
	}
}

// TestAllCipherSuites 确认 AllCipherSuites 委托 LegacyCipherSuites。
func TestAllCipherSuites(t *testing.T) {
	all := AllCipherSuites()
	legacy := LegacyCipherSuites()
	if len(all) != len(legacy) {
		t.Fatalf("AllCipherSuites len = %d, want %d", len(all), len(legacy))
	}
}

// TestIsTLCPCipherSuite 验证包内 TLCP 套件识别(仅 4 个 GB/T 38636 套件)。
func TestIsTLCPCipherSuite(t *testing.T) {
	tlcpSuites := []uint16{
		SuiteECDHE_SM2_SM4_GCM_SM3,
		SuiteECDHE_SM2_SM4_CBC_SM3,
		SuiteECC_SM2_SM4_GCM_SM3,
		SuiteECC_SM2_SM4_CBC_SM3,
	}
	for _, s := range tlcpSuites {
		if !IsTLCPCipherSuite(s) {
			t.Errorf("IsTLCPCipherSuite(0x%04X) = false, want true", s)
		}
	}
	if IsTLCPCipherSuite(0x0000) {
		t.Error("IsTLCPCipherSuite(0x0000) = true, want false")
	}
}

// TestIsCipherSuite 验证 IsCipherSuite 委托给 polluxtls.IsNationalCipherSuite(范围更广)。
func TestIsCipherSuite(t *testing.T) {
	if !IsCipherSuite(SuiteECDHE_SM2_SM4_GCM_SM3) {
		t.Error("IsCipherSuite(ECDHE_SM4_GCM) = false, want true")
	}
	// IsCipherSuite 委托 polluxtls,应与之一致
	if IsCipherSuite(0x0000) != polluxtls.IsNationalCipherSuite(0x0000) {
		t.Error("IsCipherSuite diverges from polluxtls.IsNationalCipherSuite")
	}
}

// TestGetCipherSuiteName 验证套件名称查询。
func TestGetCipherSuiteName(t *testing.T) {
	name := CipherSuiteName(SuiteECDHE_SM2_SM4_GCM_SM3)
	if name == "" {
		t.Fatal("CipherSuiteName returned empty for valid TLCP suite")
	}
	// 未知套件委托给 stdlib tls.CipherSuiteName,不应 panic
	_ = CipherSuiteName(0x0000)
}
