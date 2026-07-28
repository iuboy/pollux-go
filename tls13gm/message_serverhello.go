package tls13gm

import (
	"errors"
	"fmt"
)

// ServerHelloMsg is the TLS 1.3 ServerHello (RFC 8446 §4.1.3).
type ServerHelloMsg struct {
	// LegacyVersion is the legacy_version field (always 0x0303 in TLS 1.3).
	LegacyVersion uint16
	// Random is the 32-byte server random.
	Random [32]byte
	// LegacySessionID echoes the client's legacy_session_id.
	LegacySessionID []byte
	// CipherSuite is the selected cipher suite (exactly one).
	CipherSuite uint16
	// Extensions carries supported_versions and key_share (and optionally others).
	Extensions []Extension
}

func (*ServerHelloMsg) msgType() uint8 { return HandshakeTypeServerHello }

func (m *ServerHelloMsg) marshalBody() ([]byte, error) {
	if len(m.LegacySessionID) > 32 {
		return nil, fmt.Errorf("tls13gm: ServerHello legacy_session_id length %d exceeds 32", len(m.LegacySessionID))
	}
	out := make([]byte, 0, 96)
	out = append(out, byte(m.LegacyVersion>>8), byte(m.LegacyVersion))
	out = append(out, m.Random[:]...)
	out = append(out, byte(len(m.LegacySessionID)))
	out = append(out, m.LegacySessionID...)
	out = append(out, byte(m.CipherSuite>>8), byte(m.CipherSuite))
	out = append(out, 0x00) // legacy_compression_method: null
	exts, err := marshalExtensions(m.Extensions)
	if err != nil {
		return nil, fmt.Errorf("tls13gm: ServerHello extensions: %w", err)
	}
	out = append(out, exts...)
	return out, nil
}

func (m *ServerHelloMsg) unmarshalBody(b []byte) error {
	p := 0
	if len(b) < p+2+32 {
		return errors.New("tls13gm: ServerHello truncated before session id")
	}
	m.LegacyVersion = uint16(b[p])<<8 | uint16(b[p+1])
	p += 2
	copy(m.Random[:], b[p:p+32])
	p += 32

	if p >= len(b) {
		return errors.New("tls13gm: ServerHello truncated at session id length")
	}
	sidLen := int(b[p])
	p++
	if p+sidLen > len(b) || sidLen > 32 {
		return fmt.Errorf("tls13gm: ServerHello legacy_session_id length %d out of range", sidLen)
	}
	m.LegacySessionID = append([]byte(nil), b[p:p+sidLen]...)
	p += sidLen

	if p+2+1 > len(b) {
		return errors.New("tls13gm: ServerHello truncated at cipher suite / compression")
	}
	m.CipherSuite = uint16(b[p])<<8 | uint16(b[p+1])
	p += 2
	// legacy_compression_method: a single null byte; validate and skip.
	if b[p] != 0x00 {
		return fmt.Errorf("tls13gm: ServerHello legacy_compression_method %#x is not null", b[p])
	}
	p++

	exts, n, err := parseExtensions(b[p:])
	if err != nil {
		return fmt.Errorf("tls13gm: ServerHello extensions: %w", err)
	}
	m.Extensions = exts
	p += n
	if p != len(b) {
		return fmt.Errorf("tls13gm: ServerHello has %d trailing bytes", len(b)-p)
	}
	return nil
}
