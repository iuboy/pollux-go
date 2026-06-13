package tls13gm

import "fmt"

// FinishedMsg is the TLS 1.3 Finished message (RFC 8446 §4.4.4): a bare
// verify_data blob. For SM4-GCM/SM3 its length is the HMAC-SM3 output size
// (32 bytes), but the message stores it verbatim so no length is hardcoded.
type FinishedMsg struct {
	VerifyData []byte
}

func (*FinishedMsg) msgType() uint8 { return HandshakeTypeFinished }

func (m *FinishedMsg) marshalBody() ([]byte, error) {
	if len(m.VerifyData) == 0 {
		return nil, fmt.Errorf("tls13gm: Finished verify_data is empty")
	}
	return append([]byte(nil), m.VerifyData...), nil
}

func (m *FinishedMsg) unmarshalBody(b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("tls13gm: Finished verify_data is empty")
	}
	m.VerifyData = append([]byte(nil), b...)
	return nil
}
