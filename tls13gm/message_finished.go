package tls13gm

import (
	"fmt"

	"github.com/iuboy/pollux-go/sm3"
)

// FinishedMsg is the TLS 1.3 Finished message (RFC 8446 §4.4.4): a bare
// verify_data blob. For SM4-GCM/SM3 its length is the HMAC-SM3 output size
// (32 bytes), but the message stores it verbatim so no length is hardcoded.
type FinishedMsg struct {
	VerifyData []byte
}

func (*FinishedMsg) msgType() uint8 { return HandshakeTypeFinished }

func (m *FinishedMsg) marshalBody() ([]byte, error) {
	if len(m.VerifyData) != sm3.Size {
		return nil, fmt.Errorf("tls13gm: Finished verify_data length %d != Hash.length (%d)", len(m.VerifyData), sm3.Size)
	}
	return append([]byte(nil), m.VerifyData...), nil
}

func (m *FinishedMsg) unmarshalBody(b []byte) error {
	// RFC 8446 §4.4.4: verify_data length is exactly Hash.length for the
	// negotiated cipher suite. For SM4-GCM/SM3 this is sm3.Size (32). Require an
	// exact match rather than the previous "4×Hash.length" upper bound, which
	// accepted malformed Finished messages up to 128 bytes and only let them be
	// rejected later by the Finished HMAC check.
	if len(b) != sm3.Size {
		return fmt.Errorf("tls13gm: Finished verify_data length %d != Hash.length (%d)", len(b), sm3.Size)
	}
	m.VerifyData = append([]byte(nil), b...)
	return nil
}
