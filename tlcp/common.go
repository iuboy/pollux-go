package tlcp

// TLCP cipher suite IDs (GB/T 38636-2020 Table 2).
// Values are identical to gotlcp constants such as TLCP_ECDHE_SM4_GCM_SM3.
const (
	SuiteECDHE_SM2_SM4_GCM_SM3 uint16 = 0xE051
	SuiteECDHE_SM2_SM4_CBC_SM3 uint16 = 0xE011
	SuiteECC_SM2_SM4_GCM_SM3   uint16 = 0xE053
	SuiteECC_SM2_SM4_CBC_SM3   uint16 = 0xE013
)

// DefaultCipherSuites returns the default TLCP cipher suites (GCM-only, ECDHE-only, providing forward secrecy).
// This is the recommended configuration for new connections, providing the best security.
// For legacy compatibility with non-PFS static ECC suites, use LegacyCipherSuites().
// A fresh slice is returned on every call so callers may mutate it freely.
func DefaultCipherSuites() []uint16 {
	return []uint16{
		SuiteECDHE_SM2_SM4_GCM_SM3,
	}
}

// LegacyCipherSuites returns the full cipher suite list including CBC suites.
// CBC mode has known risks such as padding oracle attacks and is only for legacy
// system compatibility. New protocols should use the GCM-only default configuration.
func LegacyCipherSuites() []uint16 {
	return []uint16{
		SuiteECDHE_SM2_SM4_GCM_SM3,
		SuiteECDHE_SM2_SM4_CBC_SM3,
		SuiteECC_SM2_SM4_GCM_SM3,
		SuiteECC_SM2_SM4_CBC_SM3,
	}
}

// IsTLCPCipherSuite reports whether id is a TLCP cipher suite.
func IsTLCPCipherSuite(id uint16) bool {
	switch id {
	case SuiteECC_SM2_SM4_GCM_SM3, SuiteECC_SM2_SM4_CBC_SM3,
		SuiteECDHE_SM2_SM4_GCM_SM3, SuiteECDHE_SM2_SM4_CBC_SM3:
		return true
	}
	return false
}
