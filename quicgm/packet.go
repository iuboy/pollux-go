package quicgm

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"sync"

	"github.com/iuboy/pollux-go/sm4"
	"github.com/iuboy/pollux-go/tls13gm"
)

// QUICPacketProtector applies RFC 9001 packet protection to QUIC packets using
// the RFC 8998 SM4-GCM cipher suite. It consumes the cryptographic primitives
// exported by tls13gm, mirroring how quic-go consumes crypto/tls.
//
// Safety: a QUICPacketProtector is safe for concurrent use. EncryptPayload,
// DecryptPayload, ApplyHeaderProtection, and RemoveHeaderProtection each acquire
// a short-lived mutex to serialize AEAD and HP block operations.
//
// Once Zero has been called the protector is unusable: every public method
// returns a distinct error rather than panicking on the nil AEAD/HP block.
type QUICPacketProtector struct {
	mu      sync.Mutex
	keys    *tls13gm.QUICPacketKeys
	aead    *tls13gm.AEAD
	hpBlock cipher.Block // SM4-ECB for header protection; created once, reused per packet
}

// sm4GCMTagSize is the fixed authentication-tag length for SM4-GCM (16 bytes,
// per GCM). Exposed as a constant so TagSize() need not touch the AEAD after
// Zero() nils it, and so callers sizing buffers don't depend on a live AEAD.
const sm4GCMTagSize = 16

// errZeroedProtector is returned by every public method after Zero() has
// dropped the AEAD/HP block, so callers get a clear error instead of a
// nil-pointer panic.
var errZeroedProtector = errors.New("quicgm: packet protector has been zeroed")

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
	hpBlock, err := sm4.NewCipher(keys.HeaderKey)
	if err != nil {
		keys.Zero()
		return nil, fmt.Errorf("quicgm: header protection cipher: %w", err)
	}
	return &QUICPacketProtector{keys: keys, aead: aead, hpBlock: hpBlock}, nil
}

// NewQUICPacketProtectorFromKeys constructs a protector directly from keys
// already derived by the handshake (e.g. tls13gm.HandshakeSecrets), avoiding a
// redundant HKDF expansion. The key bytes are SNAPSHOT (deep-copied) into the
// protector: the source keys and the protector's copies are fully independent,
// so a concurrent tls13gm.Handshaker.Zero() zeroing the HandshakeSecrets can
// never race (or tear) the protector's key material, and protector.Zero()
// clears only the protector's own copy — both sides must be zeroed at teardown.
func NewQUICPacketProtectorFromKeys(keys *tls13gm.QUICPacketKeys) (*QUICPacketProtector, error) {
	if keys == nil {
		return nil, errors.New("quicgm: nil packet keys")
	}
	own := &tls13gm.QUICPacketKeys{
		AEADKey:   append([]byte(nil), keys.AEADKey...),
		AEADIV:    append([]byte(nil), keys.AEADIV...),
		HeaderKey: append([]byte(nil), keys.HeaderKey...),
	}
	aead, err := tls13gm.NewAEAD(own.AEADKey, own.AEADIV)
	if err != nil {
		own.Zero()
		return nil, err
	}
	hpBlock, err := sm4.NewCipher(own.HeaderKey)
	if err != nil {
		own.Zero()
		return nil, fmt.Errorf("quicgm: header protection cipher: %w", err)
	}
	return &QUICPacketProtector{keys: own, aead: aead, hpBlock: hpBlock}, nil
}

// EncryptPayload encrypts a QUIC packet payload with SM4-GCM. The full packet
// number pn is used as the AEAD sequence number (nonce = IV XOR pn) and header
// is authenticated as additional data. The result has the 16-byte GCM tag
// appended (ciphertext || tag).
func (p *QUICPacketProtector) EncryptPayload(pn uint64, header, payload []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.aead == nil {
		return nil, errZeroedProtector
	}
	return p.aead.Seal(pn, payload, header)
}

// DecryptPayload decrypts a QUIC packet payload produced by EncryptPayload,
// authenticating header as additional data.
func (p *QUICPacketProtector) DecryptPayload(pn uint64, header, ciphertext []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.aead == nil {
		return nil, errZeroedProtector
	}
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
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.hpBlock == nil {
		return errZeroedProtector
	}
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
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.hpBlock == nil {
		return 0, errZeroedProtector
	}
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
	for i := range pnLen {
		buffer[pnOffset+i] ^= mask[1+i]
	}
	return decodePacketNumber(buffer[pnOffset : pnOffset+pnLen]), nil
}

// Keys returns a deep copy of the packet protection keys. To perform a key
// update, derive the next secret with tls13gm.QUICKeyUpdate and construct a new
// protector.
//
// The copy is deliberate: returning the internal pointer would let callers
// mutate the protector's keys and race a concurrent Zero(). The returned keys
// are independent — callers own their lifetime (including zeroing them) and the
// protector's Zero() still zeroes its own copy.
func (p *QUICPacketProtector) Keys() *tls13gm.QUICPacketKeys {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.keys == nil {
		return nil
	}
	// copyBytes(nil) stays nil (not an empty non-nil slice), so a post-Zero()
	// call mirrors the source's nil fields exactly.
	copyBytes := func(b []byte) []byte {
		if b == nil {
			return nil
		}
		return append([]byte(nil), b...)
	}
	return &tls13gm.QUICPacketKeys{
		AEADKey:   copyBytes(p.keys.AEADKey),
		AEADIV:    copyBytes(p.keys.AEADIV),
		HeaderKey: copyBytes(p.keys.HeaderKey),
	}
}

// TagSize returns the AEAD authentication-tag size in bytes (16 for SM4-GCM).
// It returns the fixed constant so it remains valid even after Zero() has
// dropped the AEAD, rather than panicking on a nil AEAD.
func (p *QUICPacketProtector) TagSize() int { return sm4GCMTagSize }

// Zero securely zeroes the protector's key material. The underlying QUICPacketKeys
// are zeroed, and the AEAD/block cipher references are dropped.
func (p *QUICPacketProtector) Zero() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.keys != nil {
		p.keys.Zero()
	}
	p.aead = nil
	p.hpBlock = nil
}

func (p *QUICPacketProtector) headerMask(buffer []byte, pnOffset int) ([]byte, error) {
	sampleStart := pnOffset + 4
	sampleEnd := sampleStart + tls13gm.QUICHeaderSampleLen
	if sampleEnd > len(buffer) {
		return nil, fmt.Errorf("quicgm: packet too short for header protection sample (need %d bytes at offset %d, have %d)",
			tls13gm.QUICHeaderSampleLen, sampleStart, len(buffer))
	}
	// Reuse the pre-scheduled SM4 block cipher instead of re-creating it per
	// packet (sm4.NewCipher + key schedule) via tls13gm.HeaderProtectionMask.
	mask := make([]byte, tls13gm.QUICHeaderSampleLen)
	p.hpBlock.Encrypt(mask, buffer[sampleStart:sampleEnd])
	return mask, nil
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
	for i := range pnLen {
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
