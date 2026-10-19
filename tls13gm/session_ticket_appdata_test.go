package tls13gm

// M11/M12 regression tests: the session ticket's opaque application-data
// round-trip (server transport parameters for 0-RTT restore + ValidFor0RTT).

import (
	"bytes"
	"testing"
)

func TestSessionTicket_AppDataRoundTrip(t *testing.T) {
	tek := bytes.Repeat([]byte{0x71}, SessionTicketKeyLen)
	psk := bytes.Repeat([]byte{0xA7}, 32)
	appData := []byte("server-transport-parameters-blob")

	ticket, err := EncryptSessionTicketWithData(tek, psk, 0x11223344, appData)
	if err != nil {
		t.Fatalf("EncryptSessionTicketWithData: %v", err)
	}
	gotPSK, gotAge, gotData, err := DecryptSessionTicketWithData([][]byte{tek}, ticket)
	if err != nil {
		t.Fatalf("DecryptSessionTicketWithData: %v", err)
	}
	if !bytes.Equal(gotPSK, psk) {
		t.Fatalf("psk mismatch: %x != %x", gotPSK, psk)
	}
	if gotAge != 0x11223344 {
		t.Fatalf("ticketAgeAdd = %#x", gotAge)
	}
	if !bytes.Equal(gotData, appData) {
		t.Fatalf("appData mismatch: %q != %q", gotData, appData)
	}

	// Tickets without appData decrypt with nil data (NewSessionTicket path).
	plain, err := EncryptSessionTicket(tek, psk, 7)
	if err != nil {
		t.Fatalf("EncryptSessionTicket: %v", err)
	}
	_, _, noData, err := DecryptSessionTicketWithData([][]byte{tek}, plain)
	if err != nil {
		t.Fatalf("DecryptSessionTicketWithData (no data): %v", err)
	}
	if noData != nil {
		t.Fatalf("appData = %q, want nil", noData)
	}
}

func TestSessionTicket_AppDataSurvivesTEKRotation(t *testing.T) {
	// The ticket decrypts under EITHER key with its data intact — the rotation
	// window ([current, previous]) must keep the appData path working.
	cur := bytes.Repeat([]byte{0x81}, SessionTicketKeyLen)
	prev := bytes.Repeat([]byte{0x82}, SessionTicketKeyLen)
	psk := bytes.Repeat([]byte{0xB1}, 32)
	appData := []byte("params-v1")

	ticket, err := EncryptSessionTicketWithData(prev, psk, 1, appData)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	gotPSK, _, gotData, err := DecryptSessionTicketWithData([][]byte{cur, prev}, ticket)
	if err != nil {
		t.Fatalf("decrypt under rotation window: %v", err)
	}
	if !bytes.Equal(gotPSK, psk) || !bytes.Equal(gotData, appData) {
		t.Fatalf("rotation round-trip mismatch: psk=%t data=%t", bytes.Equal(gotPSK, psk), bytes.Equal(gotData, appData))
	}
}
