package quicgm

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/iuboy/pollux-go/tls13gm"
)

// SealHandshakePacket constructs and protects a QUIC v1 Handshake packet using
// the SM4-GCM keys derived during the TLS 1.3 GM handshake
// (tls13gm.HandshakeSecrets.{Client,Server}HandshakeKeys). The Handshake packet
// is a long-header packet of type 0b10 (RFC 9000 §17.2.2); unlike the Initial
// packet it carries no token field. The packet number is encoded in 4 octets.
//
// keys is the Handshake-level packet-protection key set (the client uses its
// server-Handshake keys to read and its client-Handshake keys to write; the
// server uses the converse). payload is the plaintext frame payload (typically
// CRYPTO frames carrying TLS handshake messages).
func SealHandshakePacket(keys *tls13gm.QUICPacketKeys, dcid, scid []byte, pn uint64, payload []byte) ([]byte, error) {
	if pn > 0xFFFFFFFF {
		return nil, fmt.Errorf("quicgm: packet number %d exceeds 32 bits", pn)
	}
	protector, err := NewQUICPacketProtectorFromKeys(keys)
	if err != nil {
		return nil, err
	}
	// Note: keys are owned by the caller (a handshake secret set); do not zero
	// them here — the caller is responsible for their lifecycle.

	const pnLen = initialPacketNumberLen
	// First byte: long header (1), fixed bit (1), Handshake type (10), reserved
	// (00), packet number length - 1 (11) => 0xE3.
	firstByte := byte(0xE0) | byte(pnLen-1)

	hdr := make([]byte, 0, 64)
	hdr = append(hdr, firstByte)
	hdr = appendUint32(hdr, QUICVersion1)
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

	ciphertextLen := len(payload) + protector.TagSize()
	hdr, err = AppendVarint(hdr, uint64(pnLen+ciphertextLen))
	if err != nil {
		return nil, err
	}

	pnOffset := len(hdr)
	hdr = appendUint32(hdr, uint32(pn))

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

// OpenHandshakePacket removes protection from a QUIC v1 Handshake packet using
// the Handshake-level keys. expectedDCID is the destination connection ID the
// receiver expects; the packet's DCID must match it exactly (QUIC §17.2
// connection-ID matching prevents mis-association). It returns the version,
// scid, recovered packet number, and decrypted payload.
func OpenHandshakePacket(keys *tls13gm.QUICPacketKeys, expectedDCID, packet []byte) (version uint32, scid []byte, pn uint64, payload []byte, err error) {
	protector, err := NewQUICPacketProtectorFromKeys(keys)
	if err != nil {
		return 0, nil, 0, nil, err
	}
	// keys are caller-owned; not zeroed here.

	if len(packet) < 1 {
		return 0, nil, 0, nil, errors.New("quicgm: handshake packet too short")
	}
	if packet[0]&0x80 == 0 {
		return 0, nil, 0, nil, errors.New("quicgm: not a long-header packet")
	}
	// RFC 9000 §17.2: the Fixed Bit in long headers MUST be 1.
	if packet[0]&0x40 == 0 {
		return 0, nil, 0, nil, errors.New("quicgm: fixed bit not set in long header")
	}
	if (packet[0]>>4)&0x03 != 0b10 {
		return 0, nil, 0, nil, fmt.Errorf("quicgm: not a Handshake packet (type %02b)", (packet[0]>>4)&0x03)
	}

	pos := 1
	version, pos, err = readUint32(packet, pos)
	if err != nil {
		return 0, nil, 0, nil, err
	}
	// The Handshake-level packet-protection keys are specific to QUIC v1.
	if version != QUICVersion1 {
		return 0, nil, 0, nil, fmt.Errorf("quicgm: unsupported QUIC version 0x%08x", version)
	}
	gotDCID, pos, err := readCID(packet, pos, "dcid")
	if err != nil {
		return 0, nil, 0, nil, err
	}
	if !bytes.Equal(gotDCID, expectedDCID) {
		return 0, nil, 0, nil, fmt.Errorf("quicgm: dcid mismatch (got %d bytes, expected %d bytes)", len(gotDCID), len(expectedDCID))
	}
	scid, pos, err = readCID(packet, pos, "scid")
	if err != nil {
		return 0, nil, 0, nil, err
	}
	length, n, err := ReadVarint(packet[pos:])
	if err != nil {
		return 0, nil, 0, nil, fmt.Errorf("quicgm: read length: %w", err)
	}
	pos += n
	pnOffset := pos

	pn, err = protector.RemoveHeaderProtection(packet, pnOffset, true)
	if err != nil {
		return 0, nil, 0, nil, err
	}
	pnLen := int(packet[0]&0x03) + 1
	// RFC 9001 §5.4.2: Initial and Handshake packets MUST use a 4-octet packet
	// number encoding. A shorter encoding is a protocol violation and would
	// yield a truncated packet-number field.
	if pnLen != 4 {
		return 0, nil, 0, nil, fmt.Errorf("quicgm: handshake packet number length must be 4, got %d", pnLen)
	}

	if uint64(pnLen) > length {
		return 0, nil, 0, nil, fmt.Errorf("quicgm: declared length %d smaller than packet number %d", length, pnLen)
	}
	// Bounds-check in uint64 space to avoid int truncation on 32-bit platforms.
	if length > uint64(len(packet)-pnOffset) {
		return 0, nil, 0, nil, fmt.Errorf("quicgm: declared length %d exceeds packet tail %d", length, len(packet)-pnOffset)
	}
	ctLen := int(length) - pnLen
	headerEnd := pnOffset + pnLen
	if headerEnd+ctLen > len(packet) {
		return 0, nil, 0, nil, fmt.Errorf("quicgm: declared length %d exceeds packet tail %d", length, len(packet)-pnOffset)
	}
	headerAAD := packet[:headerEnd]
	ciphertext := packet[headerEnd : headerEnd+ctLen]

	payload, err = protector.DecryptPayload(pn, headerAAD, ciphertext)
	if err != nil {
		return 0, nil, 0, nil, err
	}
	return version, scid, pn, payload, nil
}
