package tls13gm

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// SessionTicketKeyLen is the length of a session-ticket encryption key (TEK) in
// bytes. TEKs are 16-byte SM4 keys (SM4 is a 128-bit cipher).
const SessionTicketKeyLen = 16

// sessionTicketVersion is the format version carried as the first byte of every
// encrypted ticket, and used as AEAD additional data.
const sessionTicketVersion byte = 0x01

var (
	errTicketTooShort      = errors.New("tls13gm: session ticket too short")
	errTicketVersion       = errors.New("tls13gm: unsupported session ticket version")
	errTicketNoKey         = errors.New("tls13gm: no session-ticket encryption key")
	errTicketUndecryptable = errors.New("tls13gm: session ticket failed to decrypt under every key")
)

// EncryptSessionTicket encrypts a resumption PSK into an opaque stateless
// session-ticket identity under the given TEK. The format is:
//
//	ticket = version(1) || nonce(12) || SM4-GCM(tek, iv=nonce, aad=[version], psk)
//
// The nonce is fresh per ticket so AEAD nonces never repeat. The PSK itself is
// derived by the caller (DeriveResumptionPSK) and travels encrypted; the server
// keeps no per-ticket state (the PSK is recoverable from the ticket + TEK).
func EncryptSessionTicket(tek, psk []byte) ([]byte, error) {
	if len(tek) != SessionTicketKeyLen {
		return nil, fmt.Errorf("tls13gm: session-ticket key must be %d bytes, got %d", SessionTicketKeyLen, len(tek))
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("tls13gm: session-ticket nonce: %w", err)
	}
	aead, err := NewAEAD(tek, nonce[:])
	if err != nil {
		return nil, err
	}
	ct, err := aead.Seal(0, psk, []byte{sessionTicketVersion})
	if err != nil {
		return nil, err
	}
	ticket := make([]byte, 0, 1+len(nonce)+len(ct))
	ticket = append(ticket, sessionTicketVersion)
	ticket = append(ticket, nonce[:]...)
	ticket = append(ticket, ct...)
	return ticket, nil
}

// DecryptSessionTicket recovers the PSK from an opaque ticket by trying each
// TEK in turn (current first, then historical keys during rotation). The ticket
// version is validated and used as AEAD additional data. Returns
// errTicketUndecryptable if no key decrypts it (expired ticket, wrong server,
// or tampering).
//
// Constant-time over the TEK list: every candidate key is always tried — a
// successful decrypt with an earlier key does not short-circuit the loop — so
// the wall-clock cost is independent of which (if any) key matched. This denies
// a remote timing oracle that would otherwise reveal how deep into the
// rotation window the matching key sits. Although the PSK binder is
// subsequently checked in constant time, removing the ticket-decrypt timing
// skew closes the surface at its source.
func DecryptSessionTicket(teks [][]byte, ticket []byte) ([]byte, error) {
	if len(ticket) < 1+12 {
		return nil, errTicketTooShort
	}
	if ticket[0] != sessionTicketVersion {
		return nil, fmt.Errorf("%w: %d", errTicketVersion, ticket[0])
	}
	nonce := ticket[1:13]
	ct := ticket[13:]
	if len(teks) == 0 {
		return nil, errTicketNoKey
	}
	aad := []byte{sessionTicketVersion}
	// Always try every candidate. A success records the candidate plaintext
	// instead of returning early, so the number of AEAD.Open calls is fixed at
	// len(teks) regardless of which key matched. AEAD.Open is itself
	// constant-time over the ciphertext, making the whole loop timing-uniform.
	var (
		result []byte
		ok     bool
	)
	for _, tek := range teks {
		if len(tek) != SessionTicketKeyLen {
			continue
		}
		aead, err := NewAEAD(tek, nonce)
		if err != nil {
			continue
		}
		if psk, err := aead.Open(0, ct, aad); err == nil {
			// Keep the last (most recent in rotation order) successful PSK.
			result, ok = psk, true
		}
	}
	if !ok {
		return nil, errTicketUndecryptable
	}
	return result, nil
}
