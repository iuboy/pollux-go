package quicgm

import (
	"fmt"

	"github.com/iuboy/pollux-go/tls13gm"
)

// QUICPacketProtector applies RFC 9001 packet protection to QUIC packets using
// the RFC 8998 SM4-GCM cipher suite. It consumes the cryptographic primitives
// exported by tls13gm, mirroring how quic-go consumes crypto/tls.
type QUICPacketProtector struct {
	keys *tls13gm.QUICPacketKeys
	aead *tls13gm.AEAD
}

// NewQUICPacketProtector derives packet protection keys from a QUIC traffic
// secret (RFC 9001 §5.1) and constructs a protector.
func NewQUICPacketProtector(trafficSecret []byte) (*QUICPacketProtector, error) {
	keys, err := tls13gm.DeriveQUICPacketKeys(trafficSecret)
	if err != nil {
		return nil, err
	}
	aead, err := tls13gm.NewAEAD(keys.AEADKey, keys.AEADIV)
	if err != nil {
		keys.Zero()
		return nil, err
	}
	return &QUICPacketProtector{keys: keys, aead: aead}, nil
}

// NewQUICPacketProtectorFromKeys constructs a protector directly from keys
// already derived by the handshake (e.g. tls13gm.HandshakeSecrets), avoiding a
// redundant HKDF expansion. The caller retains ownership of keys; the protector
// holds the pointer and zeroes it via Zero().
func NewQUICPacketProtectorFromKeys(keys *tls13gm.QUICPacketKeys) (*QUICPacketProtector, error) {
	if keys == nil {
		return nil, fmt.Errorf("quicgm: nil packet keys")
	}
	aead, err := tls13gm.NewAEAD(keys.AEADKey, keys.AEADIV)
	if err != nil {
		return nil, err
	}
	return &QUICPacketProtector{keys: keys, aead: aead}, nil
}

// EncryptPayload encrypts a QUIC packet payload with SM4-GCM. The full packet
// number pn is used as the AEAD sequence number (nonce = IV XOR pn) and header
// is authenticated as additional data. The result has the 16-byte GCM tag
// appended (ciphertext || tag).
func (p *QUICPacketProtector) EncryptPayload(pn uint64, header, payload []byte) ([]byte, error) {
	return p.aead.Seal(pn, payload, header)
}

// DecryptPayload decrypts a QUIC packet payload produced by EncryptPayload,
// authenticating header as additional data.
func (p *QUICPacketProtector) DecryptPayload(pn uint64, header, ciphertext []byte) ([]byte, error) {
	return p.aead.Open(pn, ciphertext, header)
}

// ApplyHeaderProtection applies QUIC header protection (RFC 9001 §5.4) in place
// to buffer, which holds the full packet (header followed by AEAD ciphertext).
// pnOffset is the byte offset of the packet number field; pnLen is its encoded
// length (1-4). isLongHeader selects the long-header (first-byte low 4 bits) or
// short-header (low 5 bits) mask. The 16-byte mask sample is read from
// buffer[pnOffset+4 : pnOffset+20]. Header protection MUST be applied after
// payload encryption.
func (p *QUICPacketProtector) ApplyHeaderProtection(buffer []byte, pnOffset, pnLen int, isLongHeader bool) error {
	if err := validateHeaderArgs(buffer, pnOffset, pnLen); err != nil {
		return err
	}
	mask, err := p.headerMask(buffer, pnOffset)
	if err != nil {
		return err
	}
	xorHeaderMask(buffer, mask, pnOffset, pnLen, isLongHeader)
	return nil
}

// RemoveHeaderProtection removes QUIC header protection (RFC 9001 §5.4) in
// place. It unmasks the first byte, derives the packet number length from the
// recovered low bits, unmasks the packet number field, and returns it as a
// big-endian integer. Callers that truncate packet numbers on the wire must
// reconstruct the full value against their expected largest packet number.
func (p *QUICPacketProtector) RemoveHeaderProtection(buffer []byte, pnOffset int, isLongHeader bool) (uint64, error) {
	if pnOffset < 1 || pnOffset >= len(buffer) {
		return 0, fmt.Errorf("quicgm: packet number offset %d out of range for buffer length %d", pnOffset, len(buffer))
	}
	mask, err := p.headerMask(buffer, pnOffset)
	if err != nil {
		return 0, err
	}
	buffer[0] ^= mask[0] & firstByteMask(isLongHeader)
	pnLen := int(buffer[0]&0x03) + 1
	if pnOffset+pnLen > len(buffer) {
		return 0, fmt.Errorf("quicgm: packet number field (offset %d, len %d) exceeds buffer length %d", pnOffset, pnLen, len(buffer))
	}
	for i := 0; i < pnLen; i++ {
		buffer[pnOffset+i] ^= mask[1+i]
	}
	return decodePacketNumber(buffer[pnOffset : pnOffset+pnLen]), nil
}

// Keys returns the packet protection keys. To perform a key update, derive the
// next secret with tls13gm.QUICKeyUpdate and construct a new protector.
func (p *QUICPacketProtector) Keys() *tls13gm.QUICPacketKeys { return p.keys }

// TagSize returns the AEAD authentication-tag size in bytes (16 for SM4-GCM).
func (p *QUICPacketProtector) TagSize() int { return p.aead.Overhead() }

// Zero securely zeroes the protector's key material.
func (p *QUICPacketProtector) Zero() {
	if p == nil || p.keys == nil {
		return
	}
	p.keys.Zero()
}

func (p *QUICPacketProtector) headerMask(buffer []byte, pnOffset int) ([]byte, error) {
	sampleStart := pnOffset + 4
	sampleEnd := sampleStart + tls13gm.QUICHeaderSampleLen
	if sampleEnd > len(buffer) {
		return nil, fmt.Errorf("quicgm: packet too short for header protection sample (need %d bytes at offset %d, have %d)",
			tls13gm.QUICHeaderSampleLen, sampleStart, len(buffer))
	}
	return tls13gm.HeaderProtectionMask(p.keys.HeaderKey, buffer[sampleStart:sampleEnd])
}

func validateHeaderArgs(buffer []byte, pnOffset, pnLen int) error {
	if pnOffset < 1 {
		return fmt.Errorf("quicgm: packet number offset %d must be >= 1", pnOffset)
	}
	if pnLen < 1 || pnLen > 4 {
		return fmt.Errorf("quicgm: packet number length %d must be 1..4", pnLen)
	}
	if pnOffset+pnLen > len(buffer) {
		return fmt.Errorf("quicgm: packet number field (offset %d, len %d) exceeds buffer length %d", pnOffset, pnLen, len(buffer))
	}
	return nil
}

func firstByteMask(isLongHeader bool) byte {
	if isLongHeader {
		return 0x0f
	}
	return 0x1f
}

func xorHeaderMask(buffer, mask []byte, pnOffset, pnLen int, isLongHeader bool) {
	buffer[0] ^= mask[0] & firstByteMask(isLongHeader)
	for i := 0; i < pnLen; i++ {
		buffer[pnOffset+i] ^= mask[1+i]
	}
}

func decodePacketNumber(pnBytes []byte) uint64 {
	var pn uint64
	for _, b := range pnBytes {
		pn = (pn << 8) | uint64(b)
	}
	return pn
}
