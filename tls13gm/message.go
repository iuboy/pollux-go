package tls13gm

import "fmt"

// handshakeMessage is implemented by every TLS 1.3 handshake message type
// (ClientHello, ServerHello, ...). marshalBody serializes the message body
// excluding the 4-byte handshake header; msgType reports the handshake type
// byte used in that header; unmarshalBody parses a body in place.
type handshakeMessage interface {
	msgType() uint8
	marshalBody() ([]byte, error)
	unmarshalBody([]byte) error
}

// MaxHandshakeMessageLen is the largest handshake message body (2^24 - 1),
// imposed by the 3-byte length field in the handshake header.
const MaxHandshakeMessageLen = 1<<24 - 1

// MarshalHandshakeMessage wraps a message body in the TLS handshake header
// [type(1) | length(3) | body] and returns the full handshake message bytes.
// The returned slice is what gets appended to the transcript and (in record or
// CRYPTO framing) carried over the wire.
func MarshalHandshakeMessage(m handshakeMessage) ([]byte, error) {
	body, err := m.marshalBody()
	if err != nil {
		return nil, err
	}
	if len(body) > MaxHandshakeMessageLen {
		return nil, fmt.Errorf("tls13gm: handshake %d message body length %d exceeds maximum", m.msgType(), len(body))
	}
	out := make([]byte, 4+len(body))
	out[0] = m.msgType()
	l := len(body)
	out[1] = byte(l >> 16)
	out[2] = byte(l >> 8)
	out[3] = byte(l)
	copy(out[4:], body)
	return out, nil
}

// ReadHandshakeMessage parses the handshake header from b and returns the type,
// the body, and the total number of bytes consumed (header + body). It verifies
// the declared body length fits within b.
func ReadHandshakeMessage(b []byte) (msgType uint8, body []byte, n int, err error) {
	if len(b) < 4 {
		return 0, nil, 0, fmt.Errorf("tls13gm: truncated handshake header (have %d bytes)", len(b))
	}
	msgType = b[0]
	bodyLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if len(b) < 4+bodyLen {
		return 0, nil, 0, fmt.Errorf("tls13gm: truncated handshake type %d body (declared %d, have %d)", msgType, bodyLen, len(b)-4)
	}
	body = b[4 : 4+bodyLen]
	return msgType, body, 4 + bodyLen, nil
}
