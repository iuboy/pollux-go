package tls13gm

import "fmt"

// Extension is a single TLS extension: its 2-byte type and raw data. Parsed
// extensions carry their data verbatim so each message can interpret it.
type Extension struct {
	Type uint16
	Data []byte
}

// marshalExtensions writes extensions as the TLS vector
// [length(2) | (type(2) | data_len(2) | data)*]. The returned slice is the full
// vector (length prefix included), ready to append into a message body.
func marshalExtensions(exts []Extension) ([]byte, error) {
	body := make([]byte, 0, 256)
	for _, e := range exts {
		if len(e.Data) > 0xFFFF {
			return nil, fmt.Errorf("tls13gm: extension %d data length %d exceeds 16 bits", e.Type, len(e.Data))
		}
		body = append(body, byte(e.Type>>8), byte(e.Type))
		body = append(body, byte(len(e.Data)>>8), byte(len(e.Data)))
		body = append(body, e.Data...)
	}
	if len(body) > 0xFFFF {
		return nil, fmt.Errorf("tls13gm: extensions vector length %d exceeds 16 bits", len(body))
	}
	out := make([]byte, 2+len(body))
	out[0] = byte(len(body) >> 8)
	out[1] = byte(len(body))
	copy(out[2:], body)
	return out, nil
}

// parseExtensions parses a TLS extensions vector (length prefix included) and
// returns the individual extensions plus the number of input bytes consumed.
func parseExtensions(b []byte) ([]Extension, int, error) {
	if len(b) < 2 {
		return nil, 0, fmt.Errorf("tls13gm: truncated extensions length (have %d bytes)", len(b))
	}
	vecLen := int(b[0])<<8 | int(b[1])
	if len(b) < 2+vecLen {
		return nil, 0, fmt.Errorf("tls13gm: truncated extensions vector (declared %d, have %d)", vecLen, len(b)-2)
	}
	exts := []Extension{}
	p := b[2 : 2+vecLen]
	for len(p) >= 4 {
		typ := uint16(p[0])<<8 | uint16(p[1])
		dataLen := int(p[2])<<8 | int(p[3])
		if len(p) < 4+dataLen {
			return nil, 0, fmt.Errorf("tls13gm: truncated extension %d data (declared %d, have %d)", typ, dataLen, len(p)-4)
		}
		exts = append(exts, Extension{Type: typ, Data: append([]byte(nil), p[4:4+dataLen]...)})
		p = p[4+dataLen:]
	}
	if len(p) != 0 {
		return nil, 0, fmt.Errorf("tls13gm: %d trailing bytes inside extensions vector", len(p))
	}
	return exts, 2 + vecLen, nil
}

// findExtension returns the data of the first extension of the given type, or
// nil if absent.
func findExtension(exts []Extension, typ uint16) []byte {
	for _, e := range exts {
		if e.Type == typ {
			return e.Data
		}
	}
	return nil
}
