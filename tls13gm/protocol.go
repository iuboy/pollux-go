package tls13gm

// TLS protocol constants consumed by the RFC 8998 handshake engine. These
// complement the cipher-suite and signature-scheme constants in constants.go.

// ProtocolVersion is a TLS protocol version carried on the wire.
type ProtocolVersion uint16

const (
	// VersionTLS13 is the TLS 1.3 wire version (RFC 8446). It appears in the
	// ClientHello/ServerHello legacy_version field and the supported_versions
	// extension.
	VersionTLS13 ProtocolVersion = 0x0303
	// VersionTLS12 is the legacy_version value TLS 1.3 clients/servers put in
	// the ClientHello/ServerHello for backward compatibility.
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
)

// TLS extension types (RFC 8446 §4.2). Only the subset needed by the RFC 8998
// handshake engine is listed.
const (
	ExtensionTypeServerName          uint16 = 0
	ExtensionTypeSupportedGroups     uint16 = 10
	ExtensionTypeSignatureAlgorithms uint16 = 13
	ExtensionTypeALPN                uint16 = 16
	ExtensionTypeKeyShare            uint16 = 40
	ExtensionTypePreSharedKey        uint16 = 41
	ExtensionTypeSupportedVersions   uint16 = 43
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
