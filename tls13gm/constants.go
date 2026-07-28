package tls13gm

// RFC 8998 cipher suite identifiers for TLS 1.3 with SM algorithms.
const (
	TLS_SM4_GCM_SM3 uint16 = 0x00C6
	TLS_SM4_CCM_SM3 uint16 = 0x00C7
)

// SM2 signature scheme identifiers.
const (
	SM2SigSM3 uint16 = 0x0708
)

// SuiteName returns a human-readable name for known RFC 8998 cipher suites.
func SuiteName(id uint16) string {
	switch id {
	case TLS_SM4_GCM_SM3:
		return "TLS_SM4_GCM_SM3"
	case TLS_SM4_CCM_SM3:
		return "TLS_SM4_CCM_SM3"
	default:
		return "unknown"
	}
}
