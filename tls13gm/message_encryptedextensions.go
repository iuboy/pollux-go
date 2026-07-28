package tls13gm

import "fmt"

// EncryptedExtensionsMsg is the TLS 1.3 EncryptedExtensions message
// (RFC 8446 §4.3.1): just a vector of extensions, which may be empty.
type EncryptedExtensionsMsg struct {
	Extensions []Extension
}

func (*EncryptedExtensionsMsg) msgType() uint8 { return HandshakeTypeEncryptedExtensions }

func (m *EncryptedExtensionsMsg) marshalBody() ([]byte, error) {
	exts, err := marshalExtensions(m.Extensions)
	if err != nil {
		return nil, fmt.Errorf("tls13gm: EncryptedExtensions: %w", err)
	}
	return exts, nil
}

func (m *EncryptedExtensionsMsg) unmarshalBody(b []byte) error {
	exts, n, err := parseExtensions(b)
	if err != nil {
		return fmt.Errorf("tls13gm: EncryptedExtensions: %w", err)
	}
	if n != len(b) {
		return fmt.Errorf("tls13gm: EncryptedExtensions has %d trailing bytes", len(b)-n)
	}
	m.Extensions = exts
	return nil
}
