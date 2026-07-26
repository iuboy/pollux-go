package tls13gm

import (
	"errors"
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
	if len(m.VerifyData) == 0 {
		return nil, errors.New("tls13gm: Finished verify_data is empty")
	}
	return append([]byte(nil), m.VerifyData...), nil
}

func (m *FinishedMsg) unmarshalBody(b []byte) error {
	if len(b) == 0 {
		return errors.New("tls13gm: Finished verify_data is empty")
	}
	// RFC 8446 §4.4.4: verify_data length is Hash.length (HMAC output) for the
	// negotiated cipher suite. For SM4-GCM/SM3 this is sm3.Size (32). Cap at a
	// small multiple to reject memory-exhaustion attempts via oversized Finished
	// messages while tolerating future hash sizes.
	if len(b) > 4*sm3.Size {
		return fmt.Errorf("tls13gm: Finished verify_data length %d exceeds 4*Hash.length", len(b))
	}
	m.VerifyData = append([]byte(nil), b...)
	return nil
}
