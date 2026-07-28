package tls13gm

import "fmt"

// CertificateVerifyMsg is the TLS 1.3 CertificateVerify message
// (RFC 8446 §4.4.3): a signature scheme and its signature. The signed content
// (64 × 0x20 || context || 0x00 || SM3(transcript)) is built and verified by
// signature.go's Sign/VerifyCertificateVerify; this message only carries the
// wire payload.
type CertificateVerifyMsg struct {
	SignatureScheme uint16
	Signature       []byte
}

func (*CertificateVerifyMsg) msgType() uint8 { return HandshakeTypeCertificateVerify }

func (m *CertificateVerifyMsg) marshalBody() ([]byte, error) {
	if len(m.Signature) > 0xFFFF {
		return nil, fmt.Errorf("tls13gm: CertificateVerify signature length %d exceeds 16 bits", len(m.Signature))
	}
	out := make([]byte, 4+len(m.Signature))
	out[0] = byte(m.SignatureScheme >> 8)
	out[1] = byte(m.SignatureScheme)
	out[2] = byte(len(m.Signature) >> 8)
	out[3] = byte(len(m.Signature))
	copy(out[4:], m.Signature)
	return out, nil
}

func (m *CertificateVerifyMsg) unmarshalBody(b []byte) error {
	if len(b) < 4 {
		return fmt.Errorf("tls13gm: CertificateVerify truncated (have %d bytes)", len(b))
	}
	m.SignatureScheme = uint16(b[0])<<8 | uint16(b[1])
	sigLen := int(b[2])<<8 | int(b[3])
	if 4+sigLen != len(b) {
		return fmt.Errorf("tls13gm: CertificateVerify signature length %d does not match body length %d", sigLen, len(b)-4)
	}
	m.Signature = append([]byte(nil), b[4:]...)
	return nil
}
