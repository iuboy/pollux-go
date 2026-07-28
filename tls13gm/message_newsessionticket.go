package tls13gm

import "fmt"

// NewSessionTicketMsg is the TLS 1.3 NewSessionTicket handshake message
// (RFC 8446 §4.6.1), sent by the server post-handshake under the 1-RTT keys to
// give the client a resumption PSK.
//
// In tls13gm the Ticket field carries the resumption PSK directly (derived via
// DeriveResumptionPSK from the resumption master secret and TicketNonce). The
// ticket travels inside the encrypted 1-RTT channel, so carrying the PSK
// verbatim is confidentiality-safe and lets the client resume without a
// server-side ticket store.
type NewSessionTicketMsg struct {
	TicketLifetime uint32 // seconds; the PSK is valid for at most this long
	TicketAgeAdd   uint32 // added to the ticket age to obfuscate it
	TicketNonce    []byte // one-time value, unique per ticket; PSK derivation input
	Ticket         []byte // the resumption PSK (identity for the pre_shared_key extension)
	Extensions     []Extension
}

func (*NewSessionTicketMsg) msgType() uint8 { return HandshakeTypeNewSessionTicket }

func (m *NewSessionTicketMsg) marshalBody() ([]byte, error) {
	if len(m.TicketNonce) > 0xFF {
		return nil, fmt.Errorf("tls13gm: NewSessionTicket ticket_nonce length %d exceeds 255", len(m.TicketNonce))
	}
	if len(m.Ticket) == 0 {
		return nil, fmt.Errorf("tls13gm: NewSessionTicket ticket is empty")
	}
	if len(m.Ticket) > 0xFFFF {
		return nil, fmt.Errorf("tls13gm: NewSessionTicket ticket length %d exceeds 16 bits", len(m.Ticket))
	}
	out := make([]byte, 0, 16+len(m.TicketNonce)+len(m.Ticket))
	out = append(out,
		byte(m.TicketLifetime>>24), byte(m.TicketLifetime>>16), byte(m.TicketLifetime>>8), byte(m.TicketLifetime))
	out = append(out,
		byte(m.TicketAgeAdd>>24), byte(m.TicketAgeAdd>>16), byte(m.TicketAgeAdd>>8), byte(m.TicketAgeAdd))
	out = append(out, byte(len(m.TicketNonce)))
	out = append(out, m.TicketNonce...)
	out = append(out, byte(len(m.Ticket)>>8), byte(len(m.Ticket)))
	out = append(out, m.Ticket...)
	exts, err := marshalExtensions(m.Extensions)
	if err != nil {
		return nil, fmt.Errorf("tls13gm: NewSessionTicket extensions: %w", err)
	}
	out = append(out, exts...)
	return out, nil
}

func (m *NewSessionTicketMsg) unmarshalBody(b []byte) error {
	p := 0
	if len(b) < p+8 {
		return fmt.Errorf("tls13gm: NewSessionTicket truncated before nonce")
	}
	m.TicketLifetime = uint32(b[p])<<24 | uint32(b[p+1])<<16 | uint32(b[p+2])<<8 | uint32(b[p+3])
	p += 4
	m.TicketAgeAdd = uint32(b[p])<<24 | uint32(b[p+1])<<16 | uint32(b[p+2])<<8 | uint32(b[p+3])
	p += 4

	if p >= len(b) {
		return fmt.Errorf("tls13gm: NewSessionTicket truncated at nonce length")
	}
	nonceLen := int(b[p])
	p++
	if p+nonceLen > len(b) {
		return fmt.Errorf("tls13gm: NewSessionTicket nonce length %d out of range", nonceLen)
	}
	m.TicketNonce = append([]byte(nil), b[p:p+nonceLen]...)
	p += nonceLen

	if p+2 > len(b) {
		return fmt.Errorf("tls13gm: NewSessionTicket truncated at ticket length")
	}
	ticketLen := int(b[p])<<8 | int(b[p+1])
	p += 2
	if ticketLen == 0 || p+ticketLen > len(b) {
		return fmt.Errorf("tls13gm: NewSessionTicket ticket length %d out of range", ticketLen)
	}
	m.Ticket = append([]byte(nil), b[p:p+ticketLen]...)
	p += ticketLen

	exts, n, err := parseExtensions(b[p:])
	if err != nil {
		return fmt.Errorf("tls13gm: NewSessionTicket extensions: %w", err)
	}
	m.Extensions = exts
	p += n
	if p != len(b) {
		return fmt.Errorf("tls13gm: NewSessionTicket has %d trailing bytes", len(b)-p)
	}
	return nil
}
