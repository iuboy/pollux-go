package tlcp

// This file defines TLCP protocol constants and auxiliary types shared by the
// handshake-message codec (engine_messages.go) and the handshake state machines
// (later phases). Values follow GB/T 38636-2020 / GM/T 0024-2023.
//
// Reference: gotlcp/tlcp/common.go (constant values consulted; independently
// organized).

// --- Handshake message type codes (GB/T 38636-2020 §6.4.5) ---
const (
	tlcpTypeClientHello        uint8 = 1
	tlcpTypeServerHello        uint8 = 2
	tlcpTypeCertificate        uint8 = 11
	tlcpTypeServerKeyExchange  uint8 = 12
	tlcpTypeCertificateRequest uint8 = 13
	tlcpTypeServerHelloDone    uint8 = 14
	tlcpTypeCertificateVerify  uint8 = 15
	tlcpTypeClientKeyExchange  uint8 = 16
	tlcpTypeFinished           uint8 = 20
)

// --- Hello-message extension type codes (GM/T 0024-2023 Appendix A) ---
const (
	tlcpExtServerName          uint16 = 0  // A.1 SNI
	tlcpExtTrustedCAKeys       uint16 = 3  // A.2 Trusted CA Indication
	tlcpExtStatusRequest       uint16 = 5  // A.3 OCSP Status Request
	tlcpExtSupportedCurves     uint16 = 10 // A.4 Supported Elliptic Curves
	tlcpExtSignatureAlgorithms uint16 = 13 // A.5 Supported Signature Algorithms
	tlcpExtALPN                uint16 = 16 // A.6 Application-Layer Protocol Negotiation
	tlcpExtClientID            uint16 = 66 // A.7 IBSDH Client ID
)

// --- TrustedAuthority identifier types (GM/T 0024-2023 A.2) ---
const (
	tlcpIDTypePreAgreed   uint8 = 0 // pre_agreed
	tlcpIDTypeX509Name    uint8 = 2 // x509_name (DistinguishedName)
	tlcpIDTypeKeySM3Hash  uint8 = 4 // key_sm3_hash (32-byte fixed)
	tlcpIDTypeCertSM3Hash uint8 = 5 // cert_sm3_hash (32-byte fixed)
)

// tlcpTrustedAuthority is one entry in the Trusted CA Indication extension.
type tlcpTrustedAuthority struct {
	IdentifierType uint8
	Identifier     []byte
}

// tlcpCurveID is a named-curve identifier (SM2 = 41, RFC 8998 §2).
type tlcpCurveID uint16

const tlcpCurveSM2 tlcpCurveID = 41

// tlcpSignatureScheme is a SignatureAndHashAlgorithm pair (GM/T 0024-2023 A.5).
// The high byte is the hash algorithm (sm3=7), the low byte the signature
// algorithm (sm2=4), so SM2+SM3 = 0x0704.
type tlcpSignatureScheme uint16

const tlcpSigSM2WithSM3 tlcpSignatureScheme = 0x0704

// tlcpVersionTLCP is the on-wire protocol version (GB/T 38636-2020 §6.2).
// Note: 0x0101, distinct from TLS 1.2's 0x0303 and TLS 1.3's 0x0304.
const tlcpVersionTLCP uint16 = 0x0101

// tlcpCertType* are CertificateRequest certificate_types values. TLCP reuses
// the TLS 1.0 values (RSA=1, DSS=2, ECDSA=64) and adds IBC=80.
const (
	tlcpCertTypeRSADSS uint8 = 2  // dss_sign
	tlcpCertTypeECDSA  uint8 = 64 // ecdsa_sign
	tlcpCertTypeIBC    uint8 = 80 // ibc
)
