package tlcp

// TLCP cipher suite IDs (GB/T 38636-2020 Table 2).
// Values are identical to gotlcp constants such as TLCP_ECDHE_SM4_GCM_SM3.
//
// allTLCP suites is the single source of truth for the full suite list.
// DefaultCipherSuites, LegacyCipherSuites, and IsTLCPCipherSuite all
// reference it so adding a new suite only needs one edit here.
var allTLPCSuites = []uint16{
	SuiteECDHE_SM2_SM4_GCM_SM3,
	SuiteECDHE_SM2_SM4_CBC_SM3,
	SuiteECC_SM2_SM4_GCM_SM3,
	SuiteECC_SM2_SM4_CBC_SM3,
}

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
//
// Derived from allTLPCSuites (the single source of truth) by filtering for the
// GCM + ECDHE suite, so adding a suite to allTLPCSuites only needs an update
// here if it should enter the default set.
func DefaultCipherSuites() []uint16 {
	out := make([]uint16, 0, len(allTLPCSuites))
	for _, s := range allTLPCSuites {
		// Default = forward-secret (ECDHE) + AEAD (GCM).
		if s == SuiteECDHE_SM2_SM4_GCM_SM3 {
			out = append(out, s)
		}
	}
	return out
}

// LegacyCipherSuites returns the full cipher suite list including CBC suites.
// CBC mode has known risks such as padding oracle attacks and is only for legacy
// system compatibility. New protocols should use the GCM-only default configuration.
//
// Returns a defensive copy of allTLPCSuites (the single source of truth) so
// adding a suite only requires editing allTLPCSuites, not this function.
func LegacyCipherSuites() []uint16 {
	return append([]uint16(nil), allTLPCSuites...)
}

// IsTLCPCipherSuite reports whether id is a TLCP cipher suite.
// Uses the allTLPCSuites source-of-truth list so adding a new suite
// only needs one edit.
func IsTLCPCipherSuite(id uint16) bool {
	for _, s := range allTLPCSuites {
		if s == id {
			return true
		}
	}
	return false
}
