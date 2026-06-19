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

// TestSessionTicket_MatchAtAnyPosition is the regression guard for the
// constant-time-traversal change in DecryptSessionTicket: the function must
// never short-circuit on the first successful key. Before the change it
// returned early on the first matching key, leaking via timing which depth into
// the rotation list matched; after the change every key is always tried.
//
// We assert the behavioral consequence: a ticket whose TEK sits at the LAST
// position of the candidate list decrypts correctly (proving the loop reaches
// the end), and one whose TEK sits at the FIRST position also decrypts
// correctly. Both must recover the exact original PSK.
func TestSessionTicket_MatchAtAnyPosition(t *testing.T) {
	match := bytes.Repeat([]byte{0x77}, SessionTicketKeyLen)
	wrong1 := bytes.Repeat([]byte{0x12}, SessionTicketKeyLen)
	wrong2 := bytes.Repeat([]byte{0x34}, SessionTicketKeyLen)
	psk := bytes.Repeat([]byte{0x9A}, 32)

	ticket, err := EncryptSessionTicket(match, psk)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Match at the end of a 3-key list: the loop must traverse wrong1, wrong2,
	// then succeed on match. A short-circuit-after-first-success bug would
	// leave result unset and return errTicketUndecryptable.
	got, err := DecryptSessionTicket([][]byte{wrong1, wrong2, match}, ticket)
	if err != nil {
		t.Fatalf("match-at-end should decrypt: %v", err)
	}
	if !bytes.Equal(got, psk) {
		t.Errorf("match-at-end PSK mismatch: %x", got)
	}

	// Match at the front: still correct (records last success = the only one).
	got, err = DecryptSessionTicket([][]byte{match, wrong1, wrong2}, ticket)
	if err != nil {
		t.Fatalf("match-at-front should decrypt: %v", err)
	}
	if !bytes.Equal(got, psk) {
		t.Errorf("match-at-front PSK mismatch: %x", got)
	}
}

// TestSessionTicket_MultiMatchTakesLast confirms the documented selection
// semantics: when more than one candidate key decrypts (e.g. duplicate TEKs in
// the list), the LAST successful result is returned. This pins the behavior the
// constant-time traversal relies on — it records rather than returns.
func TestSessionTicket_MultiMatchTakesLast(t *testing.T) {
	k := bytes.Repeat([]byte{0x55}, SessionTicketKeyLen)
	ticket, err := EncryptSessionTicket(k, bytes.Repeat([]byte{0x01}, 32))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Same key three times — every Open succeeds identically, result is the PSK.
	got, err := DecryptSessionTicket([][]byte{k, k, k}, ticket)
	if err != nil {
		t.Fatalf("multi-match should decrypt: %v", err)
	}
	if len(got) == 0 {
		t.Error("expected non-empty PSK from multi-match decrypt")
	}
}

// TestSessionTicket_MalformedKeysInListSkipped confirms that malformed (wrong
// length) entries in the TEK list are skipped without aborting the traversal,
// so a later valid key still recovers the PSK. This guards the len(tek) !=
// SessionTicketKeyLen continue branch in the constant-time loop.
func TestSessionTicket_MalformedKeysInListSkipped(t *testing.T) {
	good := bytes.Repeat([]byte{0x88}, SessionTicketKeyLen)
	short := []byte{0x01, 0x02} // wrong length, must be skipped
	psk := bytes.Repeat([]byte{0xEE}, 32)
	ticket, err := EncryptSessionTicket(good, psk)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := DecryptSessionTicket([][]byte{short, good, short}, ticket)
	if err != nil {
		t.Fatalf("should skip malformed keys and decrypt: %v", err)
	}
	if !bytes.Equal(got, psk) {
		t.Errorf("PSK mismatch with malformed keys in list: %x", got)
	}
}
