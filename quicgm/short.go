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
//
// keyPhase is the Key Phase bit (RFC 9001 §6): 0 for the initial key
// generation, 1 after a key update. The caller tracks the current generation
// and MUST flip this bit the first time it sends under a new generation so
// the receiver knows to switch to the updated keys. pollux does not enforce
// the cadence — the transport (e.g. quic-go) owns the key-update threshold.
func Seal1RTTPacket(keys *tls13gm.QUICPacketKeys, dcid []byte, pn uint64, pnLen PacketNumberLen, keyPhase bool, payload []byte) ([]byte, error) {
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

	// First byte: short header (0), fixed bit (1), then bits 4-1 carry spin,
	// reserved, key-phase, reserved; the low 2 bits encode pnLen-1. RFC 9000
	// §17.3.1 fixes the layout as 01 <spin> 1 <key-phase> <reserved*2> <pnLen>.
	// keyPhase=1 sets bit 3 (0x08) so the receiver can detect a generation
	// change (RFC 9001 §6).
	firstByte := byte(0x40) | byte(pnLen-1)
	if keyPhase {
		firstByte |= 0x08
	}

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
// expectedDCID is the destination connection ID the receiver expects; the
// short header carries no length prefix, so its length locates the packet-
// number field. NOTE: the Key Phase bit (header[0] bit 2, RFC 9001 §6) is NOT
// consumed or returned — the caller still holds the full packet header and
// reads the bit itself to decide whether to initiate key update.
func Open1RTTPacket(keys *tls13gm.QUICPacketKeys, expectedDCID []byte, largestAcked *uint64, packet []byte) (pn uint64, payload []byte, err error) {
	protector, err := NewQUICPacketProtectorFromKeys(keys)
	if err != nil {
		return 0, nil, err
	}
	// keys are caller-owned; not zeroed here.

	dcidLen := len(expectedDCID)
	// Symmetric with Seal1RTTPacket, which rejects an empty dcid: a zero-length
	// expectedDCID would make the bytes.Equal below a no-op (comparing two empty
	// slices is always true), silently skipping the connection-ID match and
	// associating the packet with any 1-RTT short-header the attacker injects.
	if dcidLen == 0 {
		return 0, nil, errors.New("quicgm: 1-RTT packet requires a non-empty expected dcid")
	}
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
