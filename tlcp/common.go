package tlcp

// allTLCPSuites is the single source of truth for the full suite list.
// DefaultCipherSuites, LegacyCipherSuites, and IsTLCPCipherSuite all
// reference it so adding a new suite only needs one edit here.
var allTLCPSuites = []uint16{
	SuiteECDHE_SM2_SM4_GCM_SM3,
	SuiteECDHE_SM2_SM4_CBC_SM3,
	SuiteECC_SM2_SM4_GCM_SM3,
	SuiteECC_SM2_SM4_CBC_SM3,
}

// TLCP cipher suite IDs (GB/T 38636-2020 Table 2). The underscore names
// deliberately mirror their standard designations (and crypto/tls's own
// naming convention, e.g. tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256).
const (
	// SuiteECDHE_SM2_SM4_GCM_SM3 is the default (PFS + AEAD) suite.
	SuiteECDHE_SM2_SM4_GCM_SM3 uint16 = 0xE051
	// SuiteECDHE_SM2_SM4_CBC_SM3 is the CBC variant of the ECDHE suite.
	SuiteECDHE_SM2_SM4_CBC_SM3 uint16 = 0xE011
	// SuiteECC_SM2_SM4_GCM_SM3 is the static-ECC (no PFS) GCM suite.
	SuiteECC_SM2_SM4_GCM_SM3 uint16 = 0xE053
	// SuiteECC_SM2_SM4_CBC_SM3 is the static-ECC CBC suite (legacy only).
	SuiteECC_SM2_SM4_CBC_SM3 uint16 = 0xE013
)

// DefaultCipherSuites returns the default TLCP cipher suites (GCM-only, ECDHE-only, providing forward secrecy).
// This is the recommended configuration for new connections, providing the best security.
// For legacy compatibility with non-PFS static ECC suites, use LegacyCipherSuites().
// A fresh slice is returned on every call so callers may mutate it freely.
//
// Derived from allTLCPSuites (the single source of truth) by filtering for the
// GCM + ECDHE suite, so adding a suite to allTLCPSuites only needs an update
// here if it should enter the default set.
func DefaultCipherSuites() []uint16 {
	out := make([]uint16, 0, len(allTLCPSuites))
	for _, s := range allTLCPSuites {
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
// Returns a defensive copy of allTLCPSuites (the single source of truth) so
// adding a suite only requires editing allTLCPSuites, not this function.
func LegacyCipherSuites() []uint16 {
	return append([]uint16(nil), allTLCPSuites...)
}

// IsTLCPCipherSuite reports whether id is a TLCP cipher suite.
// Uses the allTLCPSuites source-of-truth list so adding a new suite
// only needs one edit.
func IsTLCPCipherSuite(id uint16) bool {
	for _, s := range allTLCPSuites {
		if s == id {
			return true
		}
	}
	return false
}
