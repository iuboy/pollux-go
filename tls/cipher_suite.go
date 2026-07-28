package tls

import (
	"crypto/tls"
	"fmt"
)

// CryptoMode determines which cipher suites to use.
type CryptoMode string

const (
	// CryptoModeInternational selects standard (non-national) cipher suites.
	CryptoModeInternational CryptoMode = "international"
	// CryptoModeNational selects national cryptography (GM) cipher suites.
	CryptoModeNational CryptoMode = "national"
	// CryptoModeHybrid selects both national and standard suites, for mixed deployments.
	CryptoModeHybrid CryptoMode = "hybrid"
)

// National cipher suite IDs (GB/T 38636-2020 表2; 0x00C6/0x00C7 from RFC 8998 §3).
const (
	// TLS_SM4_GCM_SM3 is the RFC 8998 §3 TLS 1.3 suite: SM4-GCM AEAD + SM3 hash.
	// The bulk cipher is SM4 (not SM2); SM2 provides key exchange/signature separately.
	TLS_SM4_GCM_SM3            = 0x00C6
	TLS_SM4_CCM_SM3            = 0x00C7
	ECDHE_SM2_WITH_SM4_GCM_SM3 = 0xE051
	ECDHE_SM2_WITH_SM4_CBC_SM3 = 0xE011
	ECC_SM2_WITH_SM4_GCM_SM3   = 0xE053
	ECC_SM2_WITH_SM4_CBC_SM3   = 0xE013

	// TLS_SM2_GCM_SM3 was a misnomer for 0x00C6 — RFC 8998 §3 names it
	// TLS_SM4_GCM_SM3 (SM4 is the GCM bulk cipher). Kept as an alias for one release
	// to avoid breaking external callers.
	//
	// Deprecated: use TLS_SM4_GCM_SM3.
	TLS_SM2_GCM_SM3 = TLS_SM4_GCM_SM3
)

// GetCipherSuites returns cipher suites for the given mode.
//
// CryptoModeNational/CryptoModeHybrid return only GCM suites with forward
// secrecy (ECDHE) by default — the safest selection. For legacy CBC / static
// ECC suites, use LegacyNationalCipherSuites(). This package is a registry
// only (it does not perform a handshake); the IDs are not understood by the
// standard library crypto/tls.
func GetCipherSuites(mode CryptoMode) ([]uint16, error) {
	switch mode {
	case CryptoModeNational:
		return getSecureNational(), nil
	case CryptoModeHybrid:
		return append(getInternational(), getSecureNational()...), nil
	case CryptoModeInternational:
		return getInternational(), nil
	default:
		return nil, fmt.Errorf("unsupported crypto mode: %s", mode)
	}
}

// getSecureNational returns the recommended national suites: GCM with forward
// secrecy (ECDHE). CBC and static ECC suites are intentionally excluded.
func getSecureNational() []uint16 {
	return []uint16{
		ECDHE_SM2_WITH_SM4_GCM_SM3,
	}
}

func getInternational() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	}
}

func getNational() []uint16 {
	return []uint16{
		ECDHE_SM2_WITH_SM4_GCM_SM3,
		ECDHE_SM2_WITH_SM4_CBC_SM3,
		ECC_SM2_WITH_SM4_GCM_SM3,
		ECC_SM2_WITH_SM4_CBC_SM3,
	}
}

// IsNationalCipherSuite reports whether a cipher suite ID is a national suite.
func IsNationalCipherSuite(id uint16) bool {
	switch id {
	case TLS_SM4_GCM_SM3, TLS_SM4_CCM_SM3,
		ECC_SM2_WITH_SM4_GCM_SM3, ECC_SM2_WITH_SM4_CBC_SM3,
		ECDHE_SM2_WITH_SM4_GCM_SM3, ECDHE_SM2_WITH_SM4_CBC_SM3:
		return true
	}
	return false
}

// CipherSuiteName returns the name of a cipher suite.
func CipherSuiteName(id uint16) string {
	switch id {
	case TLS_SM4_GCM_SM3:
		return "TLS_SM4_GCM_SM3"
	case TLS_SM4_CCM_SM3:
		return "TLS_SM4_CCM_SM3"
	case ECC_SM2_WITH_SM4_GCM_SM3:
		return "ECC_SM2_WITH_SM4_GCM_SM3"
	case ECC_SM2_WITH_SM4_CBC_SM3:
		return "ECC_SM2_WITH_SM4_CBC_SM3"
	case ECDHE_SM2_WITH_SM4_GCM_SM3:
		return "ECDHE_SM2_WITH_SM4_GCM_SM3"
	case ECDHE_SM2_WITH_SM4_CBC_SM3:
		return "ECDHE_SM2_WITH_SM4_CBC_SM3"
	default:
		return tls.CipherSuiteName(id)
	}
}

// NationalCipherSuites returns the recommended national cipher suite list
// (GCM + ECDHE, forward secrecy) without error. Panics are impossible since
// CryptoModeNational is always valid.
func NationalCipherSuites() []uint16 {
	suites, _ := GetCipherSuites(CryptoModeNational)
	return suites
}

// LegacyNationalCipherSuites returns the full national cipher suite list,
// including CBC and static ECC suites. CBC carries padding-oracle risk and the
// static ECC suites lack forward secrecy; use only for legacy interop.
func LegacyNationalCipherSuites() []uint16 {
	return getNational()
}
