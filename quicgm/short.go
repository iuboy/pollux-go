package quicgm

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/iuboy/pollux-go/tls13gm"
)

// Seal1RTTPacket constructs and protects a QUIC v1 1-RTT packet (short header,
// RFC 9000 §17.3.1) using the application-level SM4-GCM keys
// (tls13gm.HandshakeSecrets.{Client,Server}ApplicationKeys). The short header
// has no version or length field; dcid is written without a length prefix, so
// the receiver must already know the connection ID length.
//
// pnLen selects the truncated packet-number width via the packetnumber.go
// helpers; pass PacketNumberLen4 when there is no ack feedback yet. The
// receiver reconstructs the full packet number with DecodePacketNumber against
// its largest acknowledged number.
func Seal1RTTPacket(keys *tls13gm.QUICPacketKeys, dcid []byte, pn uint64, pnLen PacketNumberLen, payload []byte) ([]byte, error) {
	if pnLen < 1 || pnLen > 4 {
		return nil, fmt.Errorf("quicgm: packet number length %d must be 1..4", pnLen)
	}
	if len(dcid) == 0 {
		return nil, errors.New("quicgm: 1-RTT packet requires a non-empty dcid")
	}
	protector, err := NewQUICPacketProtectorFromKeys(keys)
	if err != nil {
		return nil, err
	}
	// keys are caller-owned (a handshake secret set); not zeroed here.

	// First byte: short header (0), fixed bit (1), spin/reserved/key-phase = 0,
	// packet number length - 1 => 0x40 | (pnLen-1).
	firstByte := byte(0x40) | byte(pnLen-1)

	hdr := make([]byte, 0, 32)
	hdr = append(hdr, firstByte)
	hdr = append(hdr, dcid...)
	pnOffset := len(hdr)
	hdr = AppendPacketNumber(hdr, pn, pnLen)

	ciphertext, err := protector.EncryptPayload(pn, hdr, payload)
	if err != nil {
		return nil, err
	}
	packet := append(hdr, ciphertext...)

	if err := protector.ApplyHeaderProtection(packet, pnOffset, int(pnLen), false); err != nil {
		return nil, err
	}
	return packet, nil
}

// Open1RTTPacket removes protection from a 1-RTT short-header packet.
// expectedDCID is the destination connection ID the receiver expects; the short
// header carries no length prefix, so its length locates the packet-number
// field, and its value must match exactly (QUIC §17.3 connection-ID matching).
//
// largestAcked is the receiver's largest acknowledged packet number, used to
// reconstruct the full packet number from its truncated on-wire encoding via
// DecodePacketNumber (RFC 9000 §17.1). The SM4-GCM nonce is derived from the
// FULL packet number, so reconstruction MUST happen before decryption — pass
// nil only when packet-number truncation is not in effect (the on-wire value is
// already the full number, e.g. early in a connection).
func Open1RTTPacket(keys *tls13gm.QUICPacketKeys, expectedDCID []byte, largestAcked *uint64, packet []byte) (pn uint64, payload []byte, err error) {
	protector, err := NewQUICPacketProtectorFromKeys(keys)
	if err != nil {
		return 0, nil, err
	}
	// keys are caller-owned; not zeroed here.

	dcidLen := len(expectedDCID)
	if len(packet) < 1 {
		return 0, nil, errors.New("quicgm: 1-RTT packet too short")
	}
	if packet[0]&0x80 != 0 {
		return 0, nil, errors.New("quicgm: not a short-header packet")
	}
	if 1+dcidLen > len(packet) {
		return 0, nil, fmt.Errorf("quicgm: expected dcid length %d exceeds packet", dcidLen)
	}
	if !bytes.Equal(packet[1:1+dcidLen], expectedDCID) {
		return 0, nil, errors.New("quicgm: dcid mismatch")
	}
	pnOffset := 1 + dcidLen
	if pnOffset >= len(packet) {
		return 0, nil, fmt.Errorf("quicgm: dcid length %d leaves no packet number", dcidLen)
	}

	truncatedPN, err := protector.RemoveHeaderProtection(packet, pnOffset, false)
	if err != nil {
		return 0, nil, err
	}
	pnLen := PacketNumberLen(packet[0]&0x03) + 1
	// Reconstruct the full packet number before AEAD decryption: the SM4-GCM
	// nonce is IV XOR full_pn, but the wire carries only the low pnLen octets.
	if largestAcked == nil {
		pn = truncatedPN
	} else {
		pn = DecodePacketNumber(*largestAcked, truncatedPN, pnLen)
	}

	headerEnd := pnOffset + int(pnLen)
	if headerEnd > len(packet) {
		return 0, nil, errors.New("quicgm: packet number field exceeds packet length")
	}
	headerAAD := packet[:headerEnd]
	ciphertext := packet[headerEnd:]
	if len(ciphertext) < protector.TagSize() {
		return 0, nil, errors.New("quicgm: 1-RTT payload shorter than GCM tag")
	}
	payload, err = protector.DecryptPayload(pn, headerAAD, ciphertext)
	if err != nil {
		return 0, nil, err
	}
	return pn, payload, nil
}
