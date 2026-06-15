package tls13gm

import (
	"bytes"
	"testing"
)

func TestSessionTicket_RoundTrip(t *testing.T) {
	tek := bytes.Repeat([]byte{0xAB}, SessionTicketKeyLen)
	psk := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	ticket, err := EncryptSessionTicket(tek, psk)
	if err != nil {
		t.Fatalf("EncryptSessionTicket: %v", err)
	}
	if ticket[0] != sessionTicketVersion {
		t.Fatalf("ticket version = %d, want %d", ticket[0], sessionTicketVersion)
	}
	if len(ticket) <= 1+12 {
		t.Fatalf("ticket too short: %d", len(ticket))
	}
	// Two encryptions of the same PSK must differ (fresh nonce).
	ticket2, _ := EncryptSessionTicket(tek, psk)
	if bytes.Equal(ticket, ticket2) {
		t.Fatal("two ticket encryptions are identical (nonce reuse?)")
	}

	got, err := DecryptSessionTicket([][]byte{tek}, ticket)
	if err != nil {
		t.Fatalf("DecryptSessionTicket: %v", err)
	}
	if !bytes.Equal(got, psk) {
		t.Fatalf("decrypted PSK mismatch: got %x want %x", got, psk)
	}
}

func TestSessionTicket_RotationPreviousKey(t *testing.T) {
	// A ticket encrypted under the "previous" key must still decrypt when the
	// caller supplies [current, previous] (rotation window).
	old := bytes.Repeat([]byte{0x11}, SessionTicketKeyLen)
	cur := bytes.Repeat([]byte{0x22}, SessionTicketKeyLen)
	psk := bytes.Repeat([]byte{0xCD}, 32)

	ticket, err := EncryptSessionTicket(old, psk)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// After rotation, the caller passes [current, previous]; the old key is
	// still tried and must recover the PSK.
	got, err := DecryptSessionTicket([][]byte{cur, old}, ticket)
	if err != nil {
		t.Fatalf("decrypt under [cur, prev]: %v", err)
	}
	if !bytes.Equal(got, psk) {
		t.Fatalf("PSK mismatch after rotation: %x", got)
	}
}

func TestSessionTicket_RejectsUnknownKey(t *testing.T) {
	tek := bytes.Repeat([]byte{0x33}, SessionTicketKeyLen)
	wrong := bytes.Repeat([]byte{0x44}, SessionTicketKeyLen)
	psk := bytes.Repeat([]byte{0xEE}, 32)

	ticket, err := EncryptSessionTicket(tek, psk)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := DecryptSessionTicket([][]byte{wrong}, ticket); err == nil {
		t.Fatal("decrypted with wrong key (expected failure)")
	}
}

func TestSessionTicket_RejectsBadVersion(t *testing.T) {
	tek := bytes.Repeat([]byte{0x55}, SessionTicketKeyLen)
	ticket, _ := EncryptSessionTicket(tek, bytes.Repeat([]byte{0x01}, 32))
	ticket[0] = 0x02 // corrupt version
	if _, err := DecryptSessionTicket([][]byte{tek}, ticket); err == nil {
		t.Fatal("decrypted ticket with bad version")
	}
}

func TestSessionTicket_RejectsBadKeyLength(t *testing.T) {
	if _, err := EncryptSessionTicket([]byte{1, 2, 3}, bytes.Repeat([]byte{0x01}, 32)); err == nil {
		t.Fatal("EncryptSessionTicket accepted short key")
	}
}
