package tls13gm

// TLS protocol constants consumed by the RFC 8998 handshake engine. These
// complement the cipher-suite and signature-scheme constants in constants.go.

// ProtocolVersion is a TLS protocol version carried on the wire.
type ProtocolVersion uint16

const (
	// VersionTLS13 is the TLS 1.3 wire version (RFC 8446 §4.2.1), carried in the
	// supported_versions extension (0x0304). It MUST NOT be used for the
	// ClientHello/ServerHello legacy_version field, which TLS 1.3 fixes at
	// VersionTLS12 (0x0303) for backward compatibility.
	VersionTLS13 ProtocolVersion = 0x0304
	// VersionTLS12 is the legacy_version value TLS 1.3 clients/servers put in
	// the ClientHello/ServerHello record (always 0x0303, per RFC 8446 §4.1.2/4.1.3).
	VersionTLS12 ProtocolVersion = 0x0303
)

// Handshake message types (RFC 8446 §4).
const (
	HandshakeTypeClientHello         uint8 = 1
	HandshakeTypeServerHello         uint8 = 2
	HandshakeTypeNewSessionTicket    uint8 = 4
	HandshakeTypeEndOfEarlyData      uint8 = 5
	HandshakeTypeEncryptedExtensions uint8 = 8
	HandshakeTypeCertificate         uint8 = 11
	HandshakeTypeCertificateRequest  uint8 = 13
	HandshakeTypeCertificateVerify   uint8 = 15
	HandshakeTypeFinished            uint8 = 20
	HandshakeTypeKeyUpdate           uint8 = 24
	// HandshakeTypeMessageHash (254) is the synthetic message placed first in
	// the transcript when a HelloRetryRequest occurs (RFC 8446 §4.4.1).
	HandshakeTypeMessageHash uint8 = 254
)

// TLS extension types (RFC 8446 §4.2). Only the subset needed by the RFC 8998
// handshake engine is listed.
const (
	ExtensionTypeServerName          uint16 = 0
	ExtensionTypeSupportedGroups     uint16 = 10
	ExtensionTypeSignatureAlgorithms uint16 = 13
	ExtensionTypeALPN                uint16 = 16
	ExtensionTypeKeyShare            uint16 = 51 // RFC 8446 §4.2.8 (0x0033)
	ExtensionTypePreSharedKey        uint16 = 41
	// ExtensionTypeEarlyData (RFC 8446 §4.2.10) marks 0-RTT data in a ClientHello
	// and a ticket eligible for 0-RTT in a NewSessionTicket. P2 carries it in
	// NewSessionTicket; P3 wires the ClientHello side.
	ExtensionTypeEarlyData         uint16 = 42
	ExtensionTypeSupportedVersions uint16 = 43
	// ExtensionTypeCookie (RFC 8446 §4.2.2) carries the server's stateless
	// cookie in a HelloRetryRequest and the client's echo in ClientHello2.
	ExtensionTypeCookie              uint16 = 44
	ExtensionTypePSKKeyExchangeModes uint16 = 45
	// ExtensionTypeQUICTransportParams (RFC 9001 §8) carries the QUIC transport
	// parameters in ClientHello (client) / EncryptedExtensions (server). The value
	// is the raw marshaled wire.TransportParameters; tls13gm carries the bytes
	// verbatim and the QUIC transport layer unmarshals them.
	ExtensionTypeQUICTransportParams uint16 = 57 // 0x0039
)

// Alert levels and descriptions (RFC 8446 §6).
const (
	AlertLevelWarning uint8 = 1
	AlertLevelFatal   uint8 = 2

	AlertCloseNotify            uint8 = 0
	AlertUnexpectedMessage      uint8 = 10
	AlertBadRecordMAC           uint8 = 20
	AlertHandshakeFailure       uint8 = 40
	AlertBadCertificate         uint8 = 42
	AlertUnsupportedCertificate uint8 = 43
	AlertInternalError          uint8 = 80
	AlertUserCanceled           uint8 = 90
	AlertMissingExtension       uint8 = 109
	AlertUnsupportedExtension   uint8 = 110
	AlertUnrecognizedName       uint8 = 112
	AlertBadCertificateStatus   uint8 = 113
	AlertUnknownPSKIdentity     uint8 = 115
	AlertCertificateRequired    uint8 = 116
	AlertNoApplicationProtocol  uint8 = 120
)

// helloRetryRequestRandom is the sentinel ServerHello.random value that marks
// the message as a HelloRetryRequest rather than a real ServerHello
// (RFC 8446 §4.1.3).
var helloRetryRequestRandom = [32]byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xBC, 0xB9,
	0xEA, 0x86, 0x85, 0x8F, 0x27, 0x64, 0xA8, 0xAD,
	0x90, 0xC2, 0xAB, 0x3D, 0xCC, 0xE1, 0x0E, 0x33,
}
