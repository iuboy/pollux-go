package tls13gm

import (
	"errors"
	"fmt"
)

// ClientHelloMsg is the TLS 1.3 ClientHello (RFC 8446 §4.1.2), carrying only
// the fields the RFC 8998 handshake engine uses.
type ClientHelloMsg struct {
	// LegacyVersion is the legacy_version field (always 0x0303 in TLS 1.3).
	LegacyVersion uint16
	// Random is the 32-byte client random.
	Random [32]byte
	// LegacySessionID is the legacy_session_id (0..32 bytes); echoed by ServerHello.
	LegacySessionID []byte
	// CipherSuites is the offered cipher suite list.
	CipherSuites []uint16
	// Extensions carries supported_versions, signature_algorithms,
	// supported_groups, key_share, etc.
	Extensions []Extension
}

func (*ClientHelloMsg) msgType() uint8 { return HandshakeTypeClientHello }

func (m *ClientHelloMsg) marshalBody() ([]byte, error) {
	if len(m.LegacySessionID) > 32 {
		return nil, fmt.Errorf("tls13gm: ClientHello legacy_session_id length %d exceeds 32", len(m.LegacySessionID))
	}
	out := make([]byte, 0, 128)
	out = append(out, byte(m.LegacyVersion>>8), byte(m.LegacyVersion))
	out = append(out, m.Random[:]...)
	out = append(out, byte(len(m.LegacySessionID)))
	out = append(out, m.LegacySessionID...)

	csLen := 2 * len(m.CipherSuites)
	out = append(out, byte(csLen>>8), byte(csLen))
	for _, c := range m.CipherSuites {
		out = append(out, byte(c>>8), byte(c))
	}
	// legacy_compression_methods: the single null method.
	out = append(out, 0x01, 0x00)

	exts, err := marshalExtensions(m.Extensions)
	if err != nil {
		return nil, fmt.Errorf("tls13gm: ClientHello extensions: %w", err)
	}
	out = append(out, exts...)
	return out, nil
}

func (m *ClientHelloMsg) unmarshalBody(b []byte) error {
	p := 0
	if len(b) < p+2+32 {
		return errors.New("tls13gm: ClientHello truncated before session id")
	}
	m.LegacyVersion = uint16(b[p])<<8 | uint16(b[p+1])
	p += 2
	copy(m.Random[:], b[p:p+32])
	p += 32

	if p >= len(b) {
		return errors.New("tls13gm: ClientHello truncated at session id length")
	}
	sidLen := int(b[p])
	p++
	if p+sidLen > len(b) || sidLen > 32 {
		return fmt.Errorf("tls13gm: ClientHello legacy_session_id length %d out of range", sidLen)
	}
	m.LegacySessionID = append([]byte(nil), b[p:p+sidLen]...)
	p += sidLen

	if p+2 > len(b) {
		return errors.New("tls13gm: ClientHello truncated at cipher suites length")
	}
	csLen := int(b[p])<<8 | int(b[p+1])
	p += 2
	if csLen%2 != 0 || p+csLen > len(b) {
		return fmt.Errorf("tls13gm: ClientHello cipher suites length %d out of range", csLen)
	}
	m.CipherSuites = make([]uint16, csLen/2)
	for i := range m.CipherSuites {
		m.CipherSuites[i] = uint16(b[p+2*i])<<8 | uint16(b[p+2*i+1])
	}
	p += csLen

	if p >= len(b) {
		return errors.New("tls13gm: ClientHello truncated at compression methods")
	}
	cmLen := int(b[p])
	p++
	if p+cmLen > len(b) || cmLen < 1 {
		return fmt.Errorf("tls13gm: ClientHello compression methods length %d out of range", cmLen)
	}
	// TLS 1.3 requires exactly the null method; we tolerate the vector but do
	// not store it.
	p += cmLen

	exts, n, err := parseExtensions(b[p:])
	if err != nil {
		return fmt.Errorf("tls13gm: ClientHello extensions: %w", err)
	}
	m.Extensions = exts
	p += n
	if p != len(b) {
		return fmt.Errorf("tls13gm: ClientHello has %d trailing bytes", len(b)-p)
	}
	return nil
}
