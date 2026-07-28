package quicgm

import (
	"errors"
	"fmt"

	"github.com/iuboy/pollux-go/tls13gm"
)

// QUICVersion1 is the QUIC version 1 wire value (RFC 9000).
const QUICVersion1 uint32 = 0x00000001

// initialPacketNumberLen is the fixed packet-number field width used for
// Initial packets. QUIC permits the smallest encoding that the receiver can
// decode (RFC 9000 §17.1); we use the full 4 octets, which is always valid and
// avoids packet-number truncation/reconstruction complexity. Truncation is left
// as a future transport optimization.
const initialPacketNumberLen = 4

// SealInitialPacket constructs and protects a QUIC v1 Initial packet as sent by
// the client, using RFC 8998 SM4-GCM. Packet protection keys are derived from
// dcid via the client Initial secret (RFC 9001 §5.2). The packet number pn is
// encoded in 4 octets; payload is the plaintext QUIC frame payload. The returned
// packet is fully protected (payload AEAD + header protection).
//
// dcid must be non-empty (it seeds the Initial secret); token may be nil. The
// caller is responsible for any QUIC padding (e.g. to the 1200-byte minimum
// Initial size) — padding bytes belong in payload.
func SealInitialPacket(dcid, scid, token []byte, pn uint64, payload []byte) ([]byte, error) {
	if pn > 0xFFFFFFFF {
		return nil, fmt.Errorf("quicgm: packet number %d exceeds 32 bits", pn)
	}
	clientIn, _, err := tls13gm.DeriveQUICInitialSecrets(dcid)
	if err != nil {
		return nil, fmt.Errorf("quicgm: derive initial secret: %w", err)
	}
	protector, err := NewQUICPacketProtector(clientIn)
	if err != nil {
		return nil, err
	}
	defer protector.Zero()

	const pnLen = initialPacketNumberLen
	// First byte: long header (1), fixed bit (1), Initial type (00), reserved
	// (00), packet number length - 1 (11) => 0xC3. Reserved bits stay 0; header
	// protection will mask the low 4 bits of this byte.
	firstByte := byte(0xC0) | byte(pnLen-1)

	// Build the header up to and including the Length field.
	hdr := make([]byte, 0, 64)
	hdr = append(hdr, firstByte)
	hdr = appendUint32(hdr, QUICVersion1)
	if len(dcid) == 0 {
		return nil, errors.New("quicgm: dcid must be non-empty (it seeds the Initial secret)")
	}
	if err := checkCIDLen("dcid", dcid); err != nil {
		return nil, err
	}
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	if err := checkCIDLen("scid", scid); err != nil {
		return nil, err
	}
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr, err = AppendVarint(hdr, uint64(len(token)))
	if err != nil {
		return nil, err
	}
	hdr = append(hdr, token...)

	// Length covers the packet number plus ciphertext (payload + GCM tag).
	ciphertextLen := len(payload) + protector.TagSize()
	hdr, err = AppendVarint(hdr, uint64(pnLen+ciphertextLen))
	if err != nil {
		return nil, err
	}

	pnOffset := len(hdr)
	hdr = appendUint32(hdr, uint32(pn)) // packet number (plaintext before HP)

	// headerAAD spans the first byte through the end of the packet number field.
	ciphertext, err := protector.EncryptPayload(pn, hdr, payload)
	if err != nil {
		return nil, err
	}
	packet := append(hdr, ciphertext...)

	if err := protector.ApplyHeaderProtection(packet, pnOffset, pnLen, true); err != nil {
		return nil, err
	}
	return packet, nil
}

// OpenInitialPacket removes protection from a QUIC v1 Initial packet using keys
// derived from dcid (the client Initial secret). The server decodes a client's
// Initial with the same dcid that seeded those keys. It returns the version,
// scid, token, recovered packet number, and decrypted payload.
func OpenInitialPacket(dcid, packet []byte) (version uint32, scid, token []byte, pn uint64, payload []byte, err error) {
	clientIn, _, err := tls13gm.DeriveQUICInitialSecrets(dcid)
	if err != nil {
		return 0, nil, nil, 0, nil, fmt.Errorf("quicgm: derive initial secret: %w", err)
	}
	protector, err := NewQUICPacketProtector(clientIn)
	if err != nil {
		return 0, nil, nil, 0, nil, err
	}
	defer protector.Zero()

	if len(packet) < 1 {
		return 0, nil, nil, 0, nil, errors.New("quicgm: initial packet too short")
	}
	if packet[0]&0x80 == 0 {
		return 0, nil, nil, 0, nil, errors.New("quicgm: not a long-header packet")
	}
	// RFC 9000 §17.2: the Fixed Bit in long headers MUST be 1, and bits 5-4
	// encode the long-header packet type (Initial = 0b00). Validate before key
	// derivation / AEAD to reject Retry (0b10) or 0-RTT-style packets early.
	// The high 4 bits are not header-protection-eligible (RFC 9001 §5.4.1), so
	// these checks are valid before RemoveHeaderProtection.
	if packet[0]&0x40 == 0 {
		return 0, nil, nil, 0, nil, errors.New("quicgm: fixed bit not set in long header")
	}
	if packet[0]&0x30 != 0x00 {
		return 0, nil, nil, 0, nil, errors.New("quicgm: not an Initial packet (type bits set)")
	}

	pos := 1
	version, pos, err = readUint32(packet, pos)
	if err != nil {
		return 0, nil, nil, 0, nil, err
	}
	// The Seal/Open pair and key derivation are specific to QUIC v1
	// (RFC 9000/9001). Reject other versions early to avoid silent
	// misparse or cross-protocol confusion.
	if version != QUICVersion1 {
		return 0, nil, nil, 0, nil, fmt.Errorf("quicgm: unsupported QUIC version 0x%08x", version)
	}
	// DCID length + value (advance past the sender's dcid; the caller supplied dcid).
	pos, err = skipCID(packet, pos, "dcid")
	if err != nil {
		return 0, nil, nil, 0, nil, err
	}
	scid, pos, err = readCID(packet, pos, "scid")
	if err != nil {
		return 0, nil, nil, 0, nil, err
	}
	token, pos, err = readVarintBytes(packet, pos, "token")
	if err != nil {
		return 0, nil, nil, 0, nil, err
	}
	length, n, err := ReadVarint(packet[pos:])
	if err != nil {
		return 0, nil, nil, 0, nil, fmt.Errorf("quicgm: read length: %w", err)
	}
	pos += n
	pnOffset := pos

	// Remove header protection to recover the true first byte and packet number.
	pn, err = protector.RemoveHeaderProtection(packet, pnOffset, true)
	if err != nil {
		return 0, nil, nil, 0, nil, err
	}
	pnLen := int(packet[0]&0x03) + 1
	// RFC 9001 §5.4.2: Initial packets MUST use a 4-octet packet number.
	if pnLen != 4 {
		return 0, nil, nil, 0, nil, fmt.Errorf("quicgm: initial packet number length must be 4, got %d", pnLen)
	}

	// length spans pn + ciphertext.
	if uint64(pnLen) > length {
		return 0, nil, nil, 0, nil, fmt.Errorf("quicgm: declared length %d smaller than packet number %d", length, pnLen)
	}
	ctLen := int(length) - pnLen
	headerEnd := pnOffset + pnLen
	if headerEnd+ctLen > len(packet) {
		return 0, nil, nil, 0, nil, fmt.Errorf("quicgm: declared length %d exceeds packet tail %d", length, len(packet)-pnOffset)
	}
	headerAAD := packet[:headerEnd]
	ciphertext := packet[headerEnd : headerEnd+ctLen]

	payload, err = protector.DecryptPayload(pn, headerAAD, ciphertext)
	if err != nil {
		return 0, nil, nil, 0, nil, err
	}
	return version, scid, token, pn, payload, nil
}

func appendUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func readUint32(b []byte, pos int) (uint32, int, error) {
	if pos+4 > len(b) {
		return 0, 0, fmt.Errorf("quicgm: truncated 4-octet field at offset %d", pos)
	}
	return uint32(b[pos])<<24 | uint32(b[pos+1])<<16 | uint32(b[pos+2])<<8 | uint32(b[pos+3]), pos + 4, nil
}

func checkCIDLen(name string, cid []byte) error {
	if len(cid) > 255 {
		return fmt.Errorf("quicgm: %s length %d exceeds 255", name, len(cid))
	}
	return nil
}

func readCID(b []byte, pos int, name string) ([]byte, int, error) {
	if pos+1 > len(b) {
		return nil, 0, fmt.Errorf("quicgm: truncated %s length", name)
	}
	l := int(b[pos])
	pos++
	if pos+l > len(b) {
		return nil, 0, fmt.Errorf("quicgm: truncated %s value", name)
	}
	cid := make([]byte, l)
	copy(cid, b[pos:pos+l])
	return cid, pos + l, nil
}

func skipCID(b []byte, pos int, name string) (int, error) {
	if pos+1 > len(b) {
		return 0, fmt.Errorf("quicgm: truncated %s length", name)
	}
	l := int(b[pos])
	pos++
	if pos+l > len(b) {
		return 0, fmt.Errorf("quicgm: truncated %s value", name)
	}
	return pos + l, nil
}

func readVarintBytes(b []byte, pos int, name string) ([]byte, int, error) {
	v, n, err := ReadVarint(b[pos:])
	if err != nil {
		return nil, 0, fmt.Errorf("quicgm: read %s length: %w", name, err)
	}
	start := pos + n
	end := start + int(v)
	if end > len(b) {
		return nil, 0, fmt.Errorf("quicgm: truncated %s value", name)
	}
	out := make([]byte, int(v))
	copy(out, b[start:end])
	return out, end, nil
}
