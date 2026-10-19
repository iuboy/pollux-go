package tls13gm

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/iuboy/pollux-go/internal/memsecure"
)

// SessionTicketKeyLen is the length of a session-ticket encryption key (TEK) in
// bytes. TEKs are 16-byte SM4 keys (SM4 is a 128-bit cipher).
const SessionTicketKeyLen = 16

// sessionTicketVersion is the format version carried as the first byte of every
// encrypted ticket, and used as AEAD additional data.
//
// v0x03 appends an opaque application-data blob (be32 length-prefixed, trailing)
// alongside the PSK and ticket_age_add — a QUIC transport uses it to round-trip
// the server's transport parameters so the client can restore its 0-RTT limits
// and the server can run the ValidFor0RTT admission check (RFC 8446 §4.2.10 /
// quic-go's zero-RTT model). Earlier tickets (v0x01 PSK-only, v0x02 PSK+age) are
// not accepted: a stale ticket fails to decrypt and the client falls back to a
// full handshake.
const sessionTicketVersion byte = 0x03

var (
	errTicketTooShort      = errors.New("tls13gm: session ticket too short")
	errTicketVersion       = errors.New("tls13gm: unsupported session ticket version")
	errTicketNoKey         = errors.New("tls13gm: no session-ticket encryption key")
	errTicketUndecryptable = errors.New("tls13gm: session ticket failed to decrypt under every key")
)

// EncryptSessionTicket encrypts a resumption PSK and its ticket_age_add into an
// opaque stateless session-ticket identity under the given TEK, with no
// application data. See EncryptSessionTicketWithData for the format.
func EncryptSessionTicket(tek, psk []byte, ticketAgeAdd uint32) ([]byte, error) {
	return EncryptSessionTicketWithData(tek, psk, ticketAgeAdd, nil)
}

// EncryptSessionTicketWithData encrypts a resumption PSK, its ticket_age_add,
// and an opaque application-data blob into an opaque stateless session-ticket
// identity under the given TEK. The format is:
//
//	ticket   = version(1) || nonce(12) || SM4-GCM(tek, iv=nonce, aad=[version], plaintext)
//	plaintext = psk || be32(ticketAgeAdd) || appData || be32(len(appData))
//
// The trailing length makes the variable-length fields parseable in one pass
// from the end. The nonce is fresh per ticket so AEAD nonces never repeat. The
// server keeps no per-ticket state: the PSK, the ticket_age_add needed for
// anti-replay, and the application data all travel encrypted in the ticket.
// tls13gm never interprets appData — a QUIC transport stores the server's
// marshaled transport parameters there.
func EncryptSessionTicketWithData(tek, psk []byte, ticketAgeAdd uint32, appData []byte) ([]byte, error) {
	if len(tek) != SessionTicketKeyLen {
		return nil, fmt.Errorf("tls13gm: session-ticket key must be %d bytes, got %d", SessionTicketKeyLen, len(tek))
	}
	if uint64(len(appData)) > 1<<20 {
		return nil, fmt.Errorf("tls13gm: session-ticket app data too large (%d bytes, max 1MiB)", len(appData))
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("tls13gm: session-ticket nonce: %w", err)
	}
	aead, err := NewAEAD(tek, nonce[:])
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, 0, len(psk)+4+len(appData)+4)
	plaintext = append(plaintext, psk...)
	var be32 [4]byte
	binary.BigEndian.PutUint32(be32[:], ticketAgeAdd)
	plaintext = append(plaintext, be32[:]...)
	plaintext = append(plaintext, appData...)
	binary.BigEndian.PutUint32(be32[:], uint32(len(appData)))
	plaintext = append(plaintext, be32[:]...)
	ct, err := aead.Seal(0, plaintext, []byte{sessionTicketVersion})
	if err != nil {
		return nil, err
	}
	ticket := make([]byte, 0, 1+len(nonce)+len(ct))
	ticket = append(ticket, sessionTicketVersion)
	ticket = append(ticket, nonce[:]...)
	ticket = append(ticket, ct...)
	// plaintext holds the bare PSK; it now lives only inside the sealed
	// ticket, so wipe the local copy.
	memsecure.ZeroBytes(plaintext)
	return ticket, nil
}

// DecryptSessionTicket recovers the PSK and ticket_age_add from an opaque ticket
// by trying each TEK in turn (current first, then historical keys during
// rotation). The ticket version is validated and used as AEAD additional data.
// Returns errTicketUndecryptable if no key decrypts it (expired ticket, wrong
// server, or tampering).
//
// Constant-time over the TEK list: every candidate key is always tried — a
// successful decrypt with an earlier key does not short-circuit the loop — so
// the wall-clock cost is independent of which (if any) key matched. This denies
// a remote timing oracle that would otherwise reveal how deep into the
// rotation window the matching key sits.
func DecryptSessionTicket(teks [][]byte, ticket []byte) ([]byte, uint32, error) {
	psk, ageAdd, _, err := DecryptSessionTicketWithData(teks, ticket)
	return psk, ageAdd, err
}

// DecryptSessionTicketWithData recovers the PSK, ticket_age_add, and the opaque
// application-data blob from an opaque ticket (see EncryptSessionTicketWithData
// for the plaintext layout). appData is nil for tickets issued without one.
func DecryptSessionTicketWithData(teks [][]byte, ticket []byte) ([]byte, uint32, []byte, error) {
	if len(ticket) < 1+12 {
		return nil, 0, nil, errTicketTooShort
	}
	if ticket[0] != sessionTicketVersion {
		return nil, 0, nil, fmt.Errorf("%w: %d", errTicketVersion, ticket[0])
	}
	nonce := ticket[1:13]
	ct := ticket[13:]
	if len(teks) == 0 {
		return nil, 0, nil, errTicketNoKey
	}
	aad := []byte{sessionTicketVersion}
	// Always try every candidate. A success records the candidate plaintext
	// instead of returning early, so the number of AEAD.Open calls is bounded
	// by len(teks) regardless of which key matched. AEAD.Open is itself
	// constant-time over the ciphertext.
	//
	// Timing caveat: the loop is NOT strictly uniform — keys whose length is
	// not SessionTicketKeyLen or whose NewAEAD call fails hit an early
	// `continue` and skip the AEAD.Open call. In practice the rotator only
	// ever produces well-formed 16-byte keys, so this non-uniformity is not
	// observable on the happy path. If a future caller mixes malformed keys
	// into the rotation window, those should be filtered before reaching
	// this loop to preserve the timing contract.
	var (
		result  []byte
		ageAdd  uint32
		appData []byte
		ok      bool
	)
	for _, tek := range teks {
		if len(tek) != SessionTicketKeyLen {
			continue
		}
		aead, err := NewAEAD(tek, nonce)
		if err != nil {
			continue
		}
		if pt, err := aead.Open(0, ct, aad); err == nil {
			psk, age, data, perr := parseTicketPlaintext(pt)
			if perr != nil {
				// 解析失败的明文(可能含有效 PSK)即刻擦除再试下一把钥匙。
				memsecure.ZeroBytes(pt)
				continue
			}
			// Keep the FIRST key that successfully decrypts (teks is
			// newest-first, so the first hit IS the most recent key; rotation
			// may list duplicates, where keeping the first avoids
			// re-deriving with an older entry). 保留命中返回的 psk/appData
			// 是 pt 的子切片,归调用方生命周期管理(Zero());其余命中的
			// 整套明文(含另一把有效 PSK)在此即刻擦除,不留在堆上。
			if !ok {
				result, ageAdd, appData, ok = psk, age, data, true
			} else {
				memsecure.ZeroBytes(pt)
			}
		}
	}
	if !ok {
		return nil, 0, nil, errTicketUndecryptable
	}
	return result, ageAdd, appData, nil
}

// parseTicketPlaintext splits a decrypted ticket plaintext
// (psk || be32(ageAdd) || appData || be32(len(appData))) into its fields.
func parseTicketPlaintext(pt []byte) ([]byte, uint32, []byte, error) {
	if len(pt) < 8 {
		return nil, 0, nil, errTicketTooShort
	}
	dataLen := int(binary.BigEndian.Uint32(pt[len(pt)-4:]))
	if dataLen > len(pt)-8 {
		return nil, 0, nil, fmt.Errorf("tls13gm: session-ticket app data length %d overruns plaintext", dataLen)
	}
	split := len(pt) - 8 - dataLen
	psk := pt[:split]
	ageAdd := binary.BigEndian.Uint32(pt[split : split+4])
	var data []byte
	if dataLen > 0 {
		data = pt[split+4 : len(pt)-4]
	}
	return psk, ageAdd, data, nil
}
