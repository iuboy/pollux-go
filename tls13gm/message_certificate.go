package tls13gm

import (
	"errors"
	"fmt"
)

// CertificateEntry is one entry in a TLS 1.3 Certificate message: a DER-encoded
// certificate followed by its per-entry extensions (RFC 8446 §4.4.2).
type CertificateEntry struct {
	Certificate []byte // DER-encoded X.509 certificate
	Extensions  []Extension
}

// CertificateMsg is the TLS 1.3 Certificate message (RFC 8446 §4.4.2). In the
// server-to-client direction CertificateRequestContext is empty.
type CertificateMsg struct {
	CertificateRequestContext []byte
	CertificateList           []CertificateEntry
}

func (*CertificateMsg) msgType() uint8 { return HandshakeTypeCertificate }

func (m *CertificateMsg) marshalBody() ([]byte, error) {
	if len(m.CertificateRequestContext) > 255 {
		return nil, fmt.Errorf("tls13gm: Certificate context length %d exceeds 255", len(m.CertificateRequestContext))
	}
	out := make([]byte, 0, 256)
	out = append(out, byte(len(m.CertificateRequestContext)))
	out = append(out, m.CertificateRequestContext...)

	// Build the certificate_list contents first to compute its 3-byte length.
	list := make([]byte, 0, 256)
	for _, e := range m.CertificateList {
		if len(e.Certificate) > MaxHandshakeMessageLen {
			return nil, fmt.Errorf("tls13gm: certificate length %d exceeds maximum", len(e.Certificate))
		}
		clen := len(e.Certificate)
		list = append(list, byte(clen>>16), byte(clen>>8), byte(clen))
		list = append(list, e.Certificate...)
		exts, err := marshalExtensions(e.Extensions)
		if err != nil {
			return nil, fmt.Errorf("tls13gm: certificate entry extensions: %w", err)
		}
		list = append(list, exts...)
	}
	if len(list) > MaxHandshakeMessageLen {
		return nil, fmt.Errorf("tls13gm: certificate_list length %d exceeds maximum", len(list))
	}
	llen := len(list)
	out = append(out, byte(llen>>16), byte(llen>>8), byte(llen))
	out = append(out, list...)
	return out, nil
}

func (m *CertificateMsg) unmarshalBody(b []byte) error {
	if len(b) < 1 {
		return errors.New("tls13gm: Certificate truncated at context length")
	}
	ctxLen := int(b[0])
	if 1+ctxLen > len(b) {
		return fmt.Errorf("tls13gm: Certificate context length %d out of range", ctxLen)
	}
	m.CertificateRequestContext = append([]byte(nil), b[1:1+ctxLen]...)
	p := 1 + ctxLen

	if p+3 > len(b) {
		return errors.New("tls13gm: Certificate truncated at list length")
	}
	listLen := int(b[p])<<16 | int(b[p+1])<<8 | int(b[p+2])
	p += 3
	if p+listLen > len(b) {
		return fmt.Errorf("tls13gm: Certificate list length %d out of range", listLen)
	}
	listEnd := p + listLen
	for p < listEnd {
		if p+3 > listEnd {
			return errors.New("tls13gm: Certificate entry truncated at cert length")
		}
		certLen := int(b[p])<<16 | int(b[p+1])<<8 | int(b[p+2])
		p += 3
		if p+certLen > listEnd || certLen == 0 {
			return fmt.Errorf("tls13gm: Certificate entry cert length %d out of range", certLen)
		}
		entry := CertificateEntry{Certificate: append([]byte(nil), b[p:p+certLen]...)}
		p += certLen
		exts, n, err := parseExtensions(b[p:listEnd])
		if err != nil {
			return fmt.Errorf("tls13gm: Certificate entry extensions: %w", err)
		}
		entry.Extensions = exts
		p += n
		m.CertificateList = append(m.CertificateList, entry)
	}
	if p != len(b) {
		return fmt.Errorf("tls13gm: Certificate has %d trailing bytes", len(b)-p)
	}
	return nil
}
