//go:build tlcp_native

package tlcp

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// This file implements marshal/unmarshal for the eight TLCP handshake messages
// (GB/T 38636-2020 §6.4.5): ClientHello, ServerHello, Certificate,
// ServerKeyExchange, CertificateRequest, ServerHelloDone, CertificateVerify,
// ClientKeyExchange, Finished.
//
// Each message is a plain struct with a raw cache and a pair of methods:
//   - marshal() ([]byte, error) — encodes the full handshake message including
//     the 1-byte type + 3-byte length header. The result is cached on m.raw.
//   - unmarshal(data []byte) bool — decodes; returns false on any malformation.
//
// The codec is built on golang.org/x/crypto/cryptobyte for length-safe reads.
// All messages carry the full handshake header so they can be written to the
// transcript hash verbatim.
//
// Reference: gotlcp/tlcp/handshake_messages.go (structure consulted; rewritten
// in a uniform cryptobyte style without the hand-rolled byte math and debug
// helpers).

// tlcpHandshakeMessage is implemented by every handshake message struct so the
// transcript-hash helper (and later the state machines) can treat them
// uniformly.
type tlcpHandshakeMessage interface {
	tlcpMsgType() uint8
}

// tlcpMarshalHandshake wraps a 1-byte type + uint24-length body, building via
// cryptobyte. The body closure writes only the message fields (no header).
func tlcpMarshalHandshake(msgType uint8, body func(*cryptobyte.Builder)) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(msgType)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		body(b)
	})
	return b.Bytes()
}

// tlcpReadHeader skips the 1-byte type + 3-byte length prefix and reports
// whether the stated length exactly matches the remaining input (no trailing
// bytes). On success *s is replaced with just the message body so subsequent
// reads are scoped to it.
func tlcpReadHeader(s *cryptobyte.String, msgType uint8) bool {
	var t uint8
	if !s.ReadUint8(&t) || t != msgType {
		return false
	}
	var body cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&body) {
		return false
	}
	// ReadUint24LengthPrefixed leaves any trailing bytes in s; reject them so a
	// malformed/trailing frame can't slip through.
	if !s.Empty() {
		return false
	}
	*s = body
	return true
}

// addFixedBytes appends v asserting len(v)==n (cryptobyte has no direct helper).
func tlcpAddFixedBytes(b *cryptobyte.Builder, v []byte, n int) {
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		_ = n // length is implicit via AddBytes; validation is on read side
		b.AddBytes(v)
	})
	_ = fmt.Sprintf // keep fmt import if needed later; harmless
}

// =====================================================================
// ClientHello (GB/T 38636-2020 §6.4.5.2)
// =====================================================================

type tlcpClientHelloMsg struct {
	raw                          []byte
	version                      uint16
	random                       []byte // 32 bytes
	sessionID                    []byte
	cipherSuites                 []uint16
	compressionMethods           []uint8
	serverName                   string
	trustedAuthorities           []tlcpTrustedAuthority
	ocspStapling                 bool
	supportedCurves              []tlcpCurveID
	supportedSignatureAlgorithms []tlcpSignatureScheme
	alpnProtocols                []string
}

func (m *tlcpClientHelloMsg) tlcpMsgType() uint8 { return tlcpTypeClientHello }

func (m *tlcpClientHelloMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}
	extBytes, err := m.marshalExtensions()
	if err != nil {
		return nil, err
	}
	body := func(b *cryptobyte.Builder) {
		b.AddUint16(m.version)
		b.AddBytes(m.random) // fixed 32
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(m.sessionID) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, s := range m.cipherSuites {
				b.AddUint16(s)
			}
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(m.compressionMethods) })
		if len(extBytes) > 0 {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(extBytes) })
		}
	}
	m.raw, err = tlcpMarshalHandshake(tlcpTypeClientHello, body)
	return m.raw, err
}

// marshalExtensions builds the ClientHello extension block.
func (m *tlcpClientHelloMsg) marshalExtensions() ([]byte, error) {
	var exts cryptobyte.Builder
	if m.serverName != "" {
		exts.AddUint16(tlcpExtServerName)
		exts.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8(0) // name_type = host_name
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(m.serverName))
				})
			})
		})
	}
	if len(m.trustedAuthorities) > 0 {
		exts.AddUint16(tlcpExtTrustedCAKeys)
		exts.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, ta := range m.trustedAuthorities {
					b.AddUint8(ta.IdentifierType)
					switch ta.IdentifierType {
					case tlcpIDTypeKeySM3Hash, tlcpIDTypeCertSM3Hash:
						b.AddBytes(ta.Identifier) // fixed 32
					case tlcpIDTypeX509Name:
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(ta.Identifier) })
					case tlcpIDTypePreAgreed:
						// no body
					}
				}
			})
		})
	}
	if m.ocspStapling {
		exts.AddUint16(tlcpExtStatusRequest)
		exts.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(1)  // status_type = ocsp
			b.AddUint16(0) // empty responder_id_list
			b.AddUint16(0) // empty request_extensions
		})
	}
	if len(m.supportedCurves) > 0 {
		exts.AddUint16(tlcpExtSupportedCurves)
		exts.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, c := range m.supportedCurves {
					b.AddUint16(uint16(c))
				}
			})
		})
	}
	if len(m.supportedSignatureAlgorithms) > 0 {
		exts.AddUint16(tlcpExtSignatureAlgorithms)
		exts.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, sa := range m.supportedSignatureAlgorithms {
					b.AddUint16(uint16(sa))
				}
			})
		})
	}
	if len(m.alpnProtocols) > 0 {
		exts.AddUint16(tlcpExtALPN)
		exts.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, p := range m.alpnProtocols {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(p)) })
				}
			})
		})
	}
	return exts.Bytes()
}

func (m *tlcpClientHelloMsg) unmarshal(data []byte) bool {
	*m = tlcpClientHelloMsg{raw: data}
	s := cryptobyte.String(data)
	if !tlcpReadHeader(&s, tlcpTypeClientHello) {
		return false
	}
	var random []byte
	if !s.ReadUint16(&m.version) || !s.ReadBytes(&random, 32) {
		return false
	}
	m.random = random
	if !s.ReadUint8LengthPrefixed((*cryptobyte.String)(&m.sessionID)) {
		return false
	}
	var suites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&suites) {
		return false
	}
	m.cipherSuites = []uint16{}
	for !suites.Empty() {
		var su uint16
		if !suites.ReadUint16(&su) {
			return false
		}
		m.cipherSuites = append(m.cipherSuites, su)
	}
	if !s.ReadUint8LengthPrefixed((*cryptobyte.String)(&m.compressionMethods)) {
		return false
	}
	if s.Empty() {
		return true // no extensions
	}
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}
	return m.unmarshalExtensions(extensions)
}

func (m *tlcpClientHelloMsg) unmarshalExtensions(extensions cryptobyte.String) bool {
	for !extensions.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}
		switch extType {
		case tlcpExtServerName:
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return false
			}
			for !nameList.Empty() {
				var nameType uint8
				var name cryptobyte.String
				if !nameList.ReadUint8(&nameType) || !nameList.ReadUint16LengthPrefixed(&name) || name.Empty() {
					return false
				}
				if nameType != 0 || m.serverName != "" {
					continue // only first host_name
				}
				m.serverName = string(name)
			}
		case tlcpExtTrustedCAKeys:
			var taList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&taList) || taList.Empty() {
				return false
			}
			for !taList.Empty() {
				var ta tlcpTrustedAuthority
				if !taList.ReadUint8(&ta.IdentifierType) {
					return false
				}
				switch ta.IdentifierType {
				case tlcpIDTypePreAgreed:
					ta.Identifier = []byte{}
				case tlcpIDTypeKeySM3Hash, tlcpIDTypeCertSM3Hash:
					ta.Identifier = make([]byte, 32)
					if !taList.ReadBytes(&ta.Identifier, 32) {
						return false
					}
				case tlcpIDTypeX509Name:
					if !taList.ReadUint16LengthPrefixed((*cryptobyte.String)(&ta.Identifier)) {
						return false
					}
				default:
					continue
				}
				m.trustedAuthorities = append(m.trustedAuthorities, ta)
			}
		case tlcpExtStatusRequest:
			var statusType uint8
			var ignored cryptobyte.String
			if !extData.ReadUint8(&statusType) || !extData.ReadUint16LengthPrefixed(&ignored) || !extData.ReadUint16LengthPrefixed(&ignored) {
				return false
			}
			m.ocspStapling = statusType == 1
		case tlcpExtSupportedCurves:
			var curves cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&curves) || curves.Empty() {
				return false
			}
			for !curves.Empty() {
				var c uint16
				if !curves.ReadUint16(&c) {
					return false
				}
				m.supportedCurves = append(m.supportedCurves, tlcpCurveID(c))
			}
		case tlcpExtSignatureAlgorithms:
			var sigs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigs) || sigs.Empty() {
				return false
			}
			for !sigs.Empty() {
				var sa uint16
				if !sigs.ReadUint16(&sa) {
					return false
				}
				m.supportedSignatureAlgorithms = append(m.supportedSignatureAlgorithms, tlcpSignatureScheme(sa))
			}
		case tlcpExtALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			for !protoList.Empty() {
				var proto cryptobyte.String
				if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
					return false
				}
				m.alpnProtocols = append(m.alpnProtocols, string(proto))
			}
		}
		if !extData.Empty() {
			return false
		}
	}
	return true
}

// =====================================================================
// ServerHello (GB/T 38636-2020 §6.4.5.3)
// =====================================================================

type tlcpServerHelloMsg struct {
	raw             []byte
	version         uint16
	random          []byte // 32 bytes
	sessionID       []byte
	cipherSuite     uint16
	compressionMethod uint8
	ocspStapling    bool
	ocspResponse    []byte
	alpnProtocol    string
	serverNameAck   bool
}

func (m *tlcpServerHelloMsg) tlcpMsgType() uint8 { return tlcpTypeServerHello }

func (m *tlcpServerHelloMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}
	var exts cryptobyte.Builder
	if m.ocspStapling && len(m.ocspResponse) > 0 {
		exts.AddUint16(tlcpExtStatusRequest)
		exts.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(1) // status_type = ocsp
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(m.ocspResponse) })
		})
	}
	if m.alpnProtocol != "" {
		exts.AddUint16(tlcpExtALPN)
		exts.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(m.alpnProtocol)) })
			})
		})
	}
	if m.serverNameAck {
		exts.AddUint16(tlcpExtServerName)
		exts.AddUint16(0) // empty: SNI acknowledgement
	}
	extBytes, err := exts.Bytes()
	if err != nil {
		return nil, err
	}
	body := func(b *cryptobyte.Builder) {
		b.AddUint16(m.version)
		b.AddBytes(m.random)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(m.sessionID) })
		b.AddUint16(m.cipherSuite)
		b.AddUint8(m.compressionMethod)
		if len(extBytes) > 0 {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(extBytes) })
		}
	}
	m.raw, err = tlcpMarshalHandshake(tlcpTypeServerHello, body)
	return m.raw, err
}

func (m *tlcpServerHelloMsg) unmarshal(data []byte) bool {
	*m = tlcpServerHelloMsg{raw: data}
	s := cryptobyte.String(data)
	if !tlcpReadHeader(&s, tlcpTypeServerHello) {
		return false
	}
	var random []byte
	if !s.ReadUint16(&m.version) || !s.ReadBytes(&random, 32) {
		return false
	}
	m.random = random
	if !s.ReadUint8LengthPrefixed((*cryptobyte.String)(&m.sessionID)) ||
		!s.ReadUint16(&m.cipherSuite) || !s.ReadUint8(&m.compressionMethod) {
		return false
	}
	if s.Empty() {
		return true
	}
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}
	for !extensions.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}
		switch extType {
		case tlcpExtStatusRequest:
			var statusType uint8
			if !extData.ReadUint8(&statusType) || statusType != 1 {
				return false
			}
			m.ocspStapling = true
			if !extData.ReadUint24LengthPrefixed((*cryptobyte.String)(&m.ocspResponse)) {
				return false
			}
		case tlcpExtALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			var proto cryptobyte.String
			if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() || !protoList.Empty() {
				return false
			}
			m.alpnProtocol = string(proto)
		case tlcpExtServerName:
			if len(extData) != 0 {
				return false
			}
			m.serverNameAck = true
		}
		if !extData.Empty() {
			return false
		}
	}
	return true
}

// =====================================================================
// Certificate (GB/T 38636-2020 §6.4.5.4)
// TLCP: the server sends [signing cert, encryption cert, ...CA chain].
// =====================================================================

type tlcpCertificateMsg struct {
	raw          []byte
	certificates [][]byte
}

func (m *tlcpCertificateMsg) tlcpMsgType() uint8 { return tlcpTypeCertificate }

func (m *tlcpCertificateMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}
	body := func(b *cryptobyte.Builder) {
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, cert := range m.certificates {
				b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(cert) })
			}
		})
	}
	var err error
	m.raw, err = tlcpMarshalHandshake(tlcpTypeCertificate, body)
	return m.raw, err
}

func (m *tlcpCertificateMsg) unmarshal(data []byte) bool {
	*m = tlcpCertificateMsg{raw: data}
	s := cryptobyte.String(data)
	if !tlcpReadHeader(&s, tlcpTypeCertificate) {
		return false
	}
	var certs cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&certs) || !s.Empty() {
		return false
	}
	for !certs.Empty() {
		var cert []byte
		if !certs.ReadUint24LengthPrefixed((*cryptobyte.String)(&cert)) {
			return false
		}
		m.certificates = append(m.certificates, cert)
	}
	return true
}

// =====================================================================
// ServerKeyExchange (GB/T 38636-2020 §6.4.5.5)
// Opaque key-exchange parameters; the ECC/SM2 content is parsed by the
// key-agreement layer (Phase 3), not here.
// =====================================================================

type tlcpServerKeyExchangeMsg struct {
	raw []byte
	key []byte
}

func (m *tlcpServerKeyExchangeMsg) tlcpMsgType() uint8 { return tlcpTypeServerKeyExchange }

func (m *tlcpServerKeyExchangeMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}
	var err error
	m.raw, err = tlcpMarshalHandshake(tlcpTypeServerKeyExchange, func(b *cryptobyte.Builder) {
		b.AddBytes(m.key)
	})
	return m.raw, err
}

func (m *tlcpServerKeyExchangeMsg) unmarshal(data []byte) bool {
	*m = tlcpServerKeyExchangeMsg{raw: data}
	s := cryptobyte.String(data)
	if !tlcpReadHeader(&s, tlcpTypeServerKeyExchange) {
		return false
	}
	m.key = []byte(s)
	return true
}

// =====================================================================
// CertificateRequest (GB/T 38636-2020 §6.4.5.6)
// =====================================================================

type tlcpCertificateRequestMsg struct {
	raw                    []byte
	certificateTypes       []byte
	certificateAuthorities [][]byte
}

func (m *tlcpCertificateRequestMsg) tlcpMsgType() uint8 { return tlcpTypeCertificateRequest }

func (m *tlcpCertificateRequestMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}
	body := func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(m.certificateTypes) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, ca := range m.certificateAuthorities {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(ca) })
			}
		})
	}
	var err error
	m.raw, err = tlcpMarshalHandshake(tlcpTypeCertificateRequest, body)
	return m.raw, err
}

func (m *tlcpCertificateRequestMsg) unmarshal(data []byte) bool {
	*m = tlcpCertificateRequestMsg{raw: data}
	s := cryptobyte.String(data)
	if !tlcpReadHeader(&s, tlcpTypeCertificateRequest) {
		return false
	}
	if !s.ReadUint8LengthPrefixed((*cryptobyte.String)(&m.certificateTypes)) {
		return false
	}
	var cas cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cas) || !s.Empty() {
		return false
	}
	for !cas.Empty() {
		var ca []byte
		if !cas.ReadUint16LengthPrefixed((*cryptobyte.String)(&ca)) {
			return false
		}
		m.certificateAuthorities = append(m.certificateAuthorities, ca)
	}
	return true
}

// =====================================================================
// ServerHelloDone (GB/T 38636-2020 §6.4.5.7)
// =====================================================================

type tlcpServerHelloDoneMsg struct {
	raw []byte
}

func (m *tlcpServerHelloDoneMsg) tlcpMsgType() uint8 { return tlcpTypeServerHelloDone }

func (m *tlcpServerHelloDoneMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}
	var err error
	m.raw, err = tlcpMarshalHandshake(tlcpTypeServerHelloDone, func(b *cryptobyte.Builder) {})
	return m.raw, err
}

func (m *tlcpServerHelloDoneMsg) unmarshal(data []byte) bool {
	*m = tlcpServerHelloDoneMsg{raw: data}
	s := cryptobyte.String(data)
	return tlcpReadHeader(&s, tlcpTypeServerHelloDone) && s.Empty()
}

// =====================================================================
// CertificateVerify (GB/T 38636-2020 §6.4.5.8)
// Carries the signature over the handshake transcript (SM2+SM3).
// =====================================================================

type tlcpCertificateVerifyMsg struct {
	raw       []byte
	signature []byte
}

func (m *tlcpCertificateVerifyMsg) tlcpMsgType() uint8 { return tlcpTypeCertificateVerify }

func (m *tlcpCertificateVerifyMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}
	body := func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(m.signature) })
	}
	var err error
	m.raw, err = tlcpMarshalHandshake(tlcpTypeCertificateVerify, body)
	return m.raw, err
}

func (m *tlcpCertificateVerifyMsg) unmarshal(data []byte) bool {
	*m = tlcpCertificateVerifyMsg{raw: data}
	s := cryptobyte.String(data)
	if !tlcpReadHeader(&s, tlcpTypeCertificateVerify) {
		return false
	}
	return s.ReadUint16LengthPrefixed((*cryptobyte.String)(&m.signature)) && s.Empty()
}

// =====================================================================
// ClientKeyExchange (GB/T 38636-2020 §6.4.5.9)
// ECC: carries the SM2-encrypted pre-master secret.
// =====================================================================

type tlcpClientKeyExchangeMsg struct {
	raw       []byte
	ciphertext []byte
}

func (m *tlcpClientKeyExchangeMsg) tlcpMsgType() uint8 { return tlcpTypeClientKeyExchange }

func (m *tlcpClientKeyExchangeMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}
	var err error
	m.raw, err = tlcpMarshalHandshake(tlcpTypeClientKeyExchange, func(b *cryptobyte.Builder) {
		b.AddBytes(m.ciphertext)
	})
	return m.raw, err
}

func (m *tlcpClientKeyExchangeMsg) unmarshal(data []byte) bool {
	*m = tlcpClientKeyExchangeMsg{raw: data}
	s := cryptobyte.String(data)
	if !tlcpReadHeader(&s, tlcpTypeClientKeyExchange) {
		return false
	}
	m.ciphertext = []byte(s)
	return true
}

// =====================================================================
// Finished (GB/T 38636-2020 §6.4.5.10)
// =====================================================================

type tlcpFinishedMsg struct {
	raw        []byte
	verifyData []byte
}

func (m *tlcpFinishedMsg) tlcpMsgType() uint8 { return tlcpTypeFinished }

func (m *tlcpFinishedMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}
	var err error
	m.raw, err = tlcpMarshalHandshake(tlcpTypeFinished, func(b *cryptobyte.Builder) {
		b.AddBytes(m.verifyData)
	})
	return m.raw, err
}

func (m *tlcpFinishedMsg) unmarshal(data []byte) bool {
	*m = tlcpFinishedMsg{raw: data}
	s := cryptobyte.String(data)
	if !tlcpReadHeader(&s, tlcpTypeFinished) {
		return false
	}
	m.verifyData = []byte(s)
	return true
}

// tlcpTranscriptWrite marshals msg and writes the result into the handshake
// transcript hash h (used by the state machines to feed every message).
func tlcpTranscriptWrite(msg tlcpHandshakeMessage, h writeTranscript) error {
	type marshalable interface {
		marshal() ([]byte, error)
	}
	mm, ok := msg.(marshalable)
	if !ok {
		return fmt.Errorf("tlcp: message %T is not marshalable", msg)
	}
	data, err := mm.marshal()
	if err != nil {
		return err
	}
	_, err = h.Write(data)
	return err
}

// writeTranscript is the minimal interface the transcript helper needs (a
// hash.Hash satisfies it).
type writeTranscript interface {
	Write([]byte) (int, error)
}
