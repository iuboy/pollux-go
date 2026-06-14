package tls13gm

import (
	"bytes"
	"testing"

	"github.com/iuboy/pollux-go/sm3"
)

func TestNewSessionTicket_RoundTrip(t *testing.T) {
	orig := &NewSessionTicketMsg{
		TicketLifetime: 7200,
		TicketAgeAdd:   0x12345678,
		TicketNonce:    []byte{0x01, 0x02, 0x03, 0x04},
		Ticket:         bytes.Repeat([]byte{0xAB}, sm3.Size), // 32-byte resumption PSK
		Extensions:     []Extension{{Type: ExtensionTypeEarlyData, Data: []byte{0}}},
	}
	full, err := MarshalHandshakeMessage(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	mt, body, _, err := ReadHandshakeMessage(full)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if mt != HandshakeTypeNewSessionTicket {
		t.Fatalf("message type %d, want %d", mt, HandshakeTypeNewSessionTicket)
	}
	var got NewSessionTicketMsg
	if err := got.unmarshalBody(body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.TicketLifetime != orig.TicketLifetime {
		t.Fatalf("TicketLifetime %d, want %d", got.TicketLifetime, orig.TicketLifetime)
	}
	if got.TicketAgeAdd != orig.TicketAgeAdd {
		t.Fatalf("TicketAgeAdd %#x, want %#x", got.TicketAgeAdd, orig.TicketAgeAdd)
	}
	if !bytes.Equal(got.TicketNonce, orig.TicketNonce) {
		t.Fatalf("TicketNonce %x, want %x", got.TicketNonce, orig.TicketNonce)
	}
	if !bytes.Equal(got.Ticket, orig.Ticket) {
		t.Fatalf("Ticket %x, want %x", got.Ticket, orig.Ticket)
	}
	if len(got.Extensions) != 1 || got.Extensions[0].Type != ExtensionTypeEarlyData {
		t.Fatalf("Extensions mismatch: %+v", got.Extensions)
	}
}

func TestNewSessionTicket_RejectsEmptyTicket(t *testing.T) {
	if _, err := (&NewSessionTicketMsg{Ticket: nil}).marshalBody(); err == nil {
		t.Fatal("marshal accepted an empty ticket")
	}
}
