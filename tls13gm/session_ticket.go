package tls13gm

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/iuboy/pollux-go/internal/memsecure"
)

// SessionTicketKeyLen is the length of a session-ticket encryption key (TEK) in
// bytes. TEKs are 16-byte SM4 keys (SM4 is a 128-bit cipher).
const SessionTicketKeyLen = 16

// maxSessionTicketLifetime is the RFC 8446 §4.6.1 ceiling (7 days) applied to
// both the ticket_lifetime advertised in the NewSessionTicket message and the
// validity encoded inside the ticket plaintext.
const maxSessionTicketLifetime uint32 = 7 * 24 * 60 * 60

// ticketClockSkewSecs 是票据过期判定容忍的时钟偏差(秒)。多机部署中签发与
// 校验可能落在不同主机,±60 秒的容忍窗避免边缘秒差把合法票据误判为过期;
// 超出窗口的偏移(签发时刻在未来的票据、滞后超过有效期+容忍窗的票据)仍
// 被 decline。
const ticketClockSkewSecs int64 = 60

// sessionTicketVersion is the format version carried as the first byte of every
// encrypted ticket, and used as AEAD additional data.
//
// v0x04 folds an issuance timestamp (be64 unix seconds) and the advertised
// validity (be32 seconds) into the plaintext, so DecryptSessionTicketWithData
// can decline expired tickets without per-ticket server state (第四轮审计 P3:
// 之前的票据永不过期)。Earlier tickets (v0x01 PSK-only, v0x02 PSK+age, v0x03
// PSK+age+appData without expiry) are not accepted: a stale ticket fails at the
// version byte and the client falls back to a full handshake.
const sessionTicketVersion byte = 0x04

// ticketTimeNow 返回当前时间;测试覆写此变量以构造确定性的过期/未过期票据。
// 生产代码不得替换(与 pwHash readRandom 的测试缝同一约定)。
var ticketTimeNow = time.Now

var (
	errTicketTooShort      = errors.New("tls13gm: session ticket too short")
	errTicketVersion       = errors.New("tls13gm: unsupported session ticket version")
	errTicketNoKey         = errors.New("tls13gm: no session-ticket encryption key")
	errTicketUndecryptable = errors.New("tls13gm: session ticket failed to decrypt under every key")
	// errTicketExpired wraps errTicketUndecryptable so existing callers that
	// match the undecryptable sentinel (errors.Is) keep declining expired
	// tickets identically, while still being able to distinguish the cause.
	errTicketExpired = fmt.Errorf("%w: expired", errTicketUndecryptable)
)

// EncryptSessionTicket encrypts a resumption PSK and its ticket_age_add into an
// opaque stateless session-ticket identity under the given TEK, with no
// application data. lifetime is the validity in seconds that the accompanying
// NewSessionTicket advertises (RFC 8446 §4.6.1 caps it at 604800; values above
// the cap are rejected). See EncryptSessionTicketWithData for the format.
func EncryptSessionTicket(tek, psk []byte, ticketAgeAdd, lifetime uint32) ([]byte, error) {
	return EncryptSessionTicketWithData(tek, psk, ticketAgeAdd, lifetime, nil)
}

// EncryptSessionTicketWithData encrypts a resumption PSK, its ticket_age_add,
// its validity window, and an opaque application-data blob into an opaque
// stateless session-ticket identity under the given TEK. The format is:
//
//	ticket    = version(1) || nonce(12) || SM4-GCM(tek, iv=nonce, aad=[version], plaintext)
//	plaintext = psk || be32(ticketAgeAdd) || be64(issuedAtUnixSec) || be32(lifetimeSec) ||
//	            appData || be32(len(appData))
//
// The trailing length makes the variable-length fields parseable in one pass
// from the end. The issuance timestamp and validity travel inside the AEAD —
// the version byte used as additional data authenticates the whole plaintext —
// so DecryptSessionTicketWithData can decline expired tickets with no
// per-ticket server state. lifetime must not exceed the RFC 8446 §4.6.1
// ceiling of 604800 seconds (7 days); zero is permitted and means the ticket
// is expired on issuance (RFC's "discard immediately" semantics). The nonce is
// fresh per ticket so AEAD nonces never repeat. The server keeps no per-ticket
// state: the PSK, the ticket_age_add needed for anti-replay, the validity
// window, and the application data all travel encrypted in the ticket.
// tls13gm never interprets appData — a QUIC transport stores the server's
// marshaled transport parameters there.
func EncryptSessionTicketWithData(tek, psk []byte, ticketAgeAdd, lifetime uint32, appData []byte) ([]byte, error) {
	if len(tek) != SessionTicketKeyLen {
		return nil, fmt.Errorf("tls13gm: session-ticket key must be %d bytes, got %d", SessionTicketKeyLen, len(tek))
	}
	if lifetime > maxSessionTicketLifetime {
		return nil, fmt.Errorf("tls13gm: session-ticket lifetime %d exceeds RFC 8446 §4.6.1 maximum %d", lifetime, maxSessionTicketLifetime)
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
	plaintext := make([]byte, 0, len(psk)+4+8+4+len(appData)+4)
	plaintext = append(plaintext, psk...)
	var beBuf [8]byte
	binary.BigEndian.PutUint32(beBuf[:4], ticketAgeAdd)
	plaintext = append(plaintext, beBuf[:4]...) // be32(ticketAgeAdd)
	binary.BigEndian.PutUint64(beBuf[:], uint64(ticketTimeNow().Unix()))
	plaintext = append(plaintext, beBuf[:]...) // be64(issuedAtUnixSec)
	binary.BigEndian.PutUint32(beBuf[:4], lifetime)
	plaintext = append(plaintext, beBuf[:4]...) // be32(lifetimeSec)
	plaintext = append(plaintext, appData...)
	binary.BigEndian.PutUint32(beBuf[:4], uint32(len(appData)))
	plaintext = append(plaintext, beBuf[:4]...)
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
// Expired tickets (validity window encoded in the plaintext elapsed) are
// declined like undecryptable ones. Returns errTicketUndecryptable if no key
// decrypts it (wrong server, tampering, or an expired ticket — errTicketExpired
// preserves that cause for errors.Is while wrapping the same sentinel).
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
// The validity window inside the plaintext is checked against the current time
// (with ticketClockSkewSecs tolerance): an expired ticket is declined —
// errTicketExpired, which wraps errTicketUndecryptable so callers treating any
// decryption failure as a PSK decline are unaffected (第四轮审计 P3).
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
		expired bool
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
			psk, age, issuedAt, lifetime, data, perr := parseTicketPlaintext(pt)
			if perr != nil {
				// 解析失败的明文(可能含有效 PSK)即刻擦除再试下一把钥匙。
				memsecure.ZeroBytes(pt)
				continue
			}
			// 过期票据按 decline 处理(与不可解密同一拒绝面),但保留
			// expired 标记以返回更精确的错误;继续遍历剩余候选钥匙,维持
			// 对 TEK 列表长度的常时遍历契约。
			if !ticketIsFresh(issuedAt, lifetime) {
				expired = true
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
		if expired {
			return nil, 0, nil, errTicketExpired
		}
		return nil, 0, nil, errTicketUndecryptable
	}
	return result, ageAdd, appData, nil
}

// ticketIsFresh reports whether the validity window [issuedAt,
// issuedAt+lifetime] covers the current time within ticketClockSkewSecs of
// tolerance. A zero lifetime is always stale (RFC 8446 "discard immediately"
// semantics). issuedAt/lifetime travel inside the AEAD, so only a legitimately
// issued ticket can reach this check — the tolerance exists for multi-host
// clock drift, not as an anti-tamper measure.
func ticketIsFresh(issuedAt int64, lifetime uint32) bool {
	if lifetime == 0 {
		return false
	}
	now := ticketTimeNow().Unix()
	if issuedAt > now+ticketClockSkewSecs {
		return false // 签发时刻超前:伪造或严重时钟漂移
	}
	if now > issuedAt+int64(lifetime)+ticketClockSkewSecs {
		return false // 已过有效期
	}
	return true
}

// parseTicketPlaintext splits a decrypted ticket plaintext
// (psk || be32(ageAdd) || be64(issuedAtUnixSec) || be32(lifetimeSec) ||
// appData || be32(len(appData))) into its fields.
func parseTicketPlaintext(pt []byte) ([]byte, uint32, int64, uint32, []byte, error) {
	// psk 之后的定长尾部:ageAdd(4) || issuedAt(8) || lifetime(4) || appDataLen(4)。
	const fixedTail = 4 + 8 + 4 + 4
	if len(pt) < fixedTail {
		return nil, 0, 0, 0, nil, errTicketTooShort
	}
	dataLen := int(binary.BigEndian.Uint32(pt[len(pt)-4:]))
	if dataLen > len(pt)-fixedTail {
		return nil, 0, 0, 0, nil, fmt.Errorf("tls13gm: session-ticket app data length %d overruns plaintext", dataLen)
	}
	split := len(pt) - fixedTail - dataLen
	psk := pt[:split]
	ageAdd := binary.BigEndian.Uint32(pt[split : split+4])
	issuedAt := int64(binary.BigEndian.Uint64(pt[split+4 : split+12]))
	lifetime := binary.BigEndian.Uint32(pt[split+12 : split+16])
	var data []byte
	if dataLen > 0 {
		data = pt[split+16 : len(pt)-4]
	}
	return psk, ageAdd, issuedAt, lifetime, data, nil
}
