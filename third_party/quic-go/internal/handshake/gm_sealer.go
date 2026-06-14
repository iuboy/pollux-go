// gm_sealer.go adapts pollux-go's tls13gm packet-protection primitives to
// quic-go's LongHeaderSealer / LongHeaderOpener / ShortHeaderSealer /
// ShortHeaderOpener interfaces (defined in interface.go). These adapters are
// the wire-level bridge between the RFC 8998 GM key material and quic-go's
// packet packer/unpacker.
//
// Why we do not reuse upstream's longHeaderSealer/longHeaderOpener structs:
// upstream's AEAD nonce scheme asserts an 8-byte nonce built from the packet
// number (see aead.go), while RFC 8446 §5.3 / RFC 9001 §5.3 use a 12-byte IV
// XOR-ed with the 64-bit sequence number. tls13gm.AEAD already implements the
// correct 12-byte scheme, so the adapters drive it directly instead of going
// through upstream's nonce construction.
//
// Header protection uses an SM4-ECB mask over the 16-byte ciphertext sample
// (RFC 9001 §5.4.3), mirroring quicgm.QUICPacketProtector so that packets
// sealed by these adapters are byte-identical to those sealed by the standalone
// quicgm path (verified by gm_sealer_test.go).

package handshake

import (
	"crypto/cipher"
	"fmt"

	"github.com/iuboy/pollux-go/sm4"
	"github.com/iuboy/pollux-go/tls13gm"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

// gmHeaderSampleLen is the header-protection sample length in bytes (RFC 9001
// §5.4.3: 16 bytes for all AEAD suites). Equal to tls13gm.QUICHeaderSampleLen.
const gmHeaderSampleLen = 16

// Compile-time interface conformance checks.
var (
	_ LongHeaderSealer = (*gmLongSealer)(nil)
	_ LongHeaderOpener = (*gmLongOpener)(nil)
	_ ShortHeaderSealer = (*gmShortSealer)(nil)
	_ ShortHeaderOpener = (*gmShortOpener)(nil)
)

// gmKeyMaterial is the shared substrate for the GM sealer/opener adapters: an
// SM4-GCM AEAD (12-byte IV + sequence-number XOR) and an SM4-ECB block cipher
// for header protection. Constructed once per encryption level from a
// tls13gm.QUICPacketKeys triple.
type gmKeyMaterial struct {
	aead *tls13gm.AEAD
	hp   cipher.Block
}

func newGMKeyMaterial(keys *tls13gm.QUICPacketKeys) (*gmKeyMaterial, error) {
	if keys == nil {
		return nil, fmt.Errorf("handshake: nil GM QUIC packet keys")
	}
	aead, err := tls13gm.NewAEAD(keys.AEADKey, keys.AEADIV)
	if err != nil {
		return nil, fmt.Errorf("handshake: GM AEAD init: %w", err)
	}
	hp, err := sm4.NewCipher(keys.HeaderKey)
	if err != nil {
		return nil, fmt.Errorf("handshake: GM header-protection cipher init: %w", err)
	}
	return &gmKeyMaterial{aead: aead, hp: hp}, nil
}

// applyGMHeaderMask computes the SM4-ECB header-protection mask over the 16-byte
// sample and applies it in place to the first byte (low 4 bits for long
// headers, low 5 for short) and the packet-number bytes. Applying the mask a
// second time with the same sample reverses it, so the same routine serves both
// EncryptHeader and DecryptHeader.
func applyGMHeaderMask(hp cipher.Block, isLongHeader bool, sample []byte, firstByte *byte, pnBytes []byte) {
	var mask [gmHeaderSampleLen]byte
	hp.Encrypt(mask[:], sample)
	if isLongHeader {
		*firstByte ^= mask[0] & 0x0f
	} else {
		*firstByte ^= mask[0] & 0x1f
	}
	for i := range pnBytes {
		pnBytes[i] ^= mask[1+i]
	}
}

// --- Long header (Initial, Handshake) ---

// gmLongSealer implements LongHeaderSealer for Initial and Handshake packets.
type gmLongSealer struct {
	km     *gmKeyMaterial
	isLong bool
}

func (s *gmLongSealer) Seal(dst, src []byte, pn protocol.PacketNumber, ad []byte) []byte {
	ct, err := s.km.aead.Seal(uint64(pn), src, ad)
	if err != nil {
		// SM4-GCM Seal with a valid key and a 12-byte nonce never fails; a
		// failure means a key-derivation bug. Panic to surface it rather than
		// silently emitting an unauthenticated packet, matching upstream's
		// longHeaderSealer which returns no error.
		panic(fmt.Sprintf("handshake: GM Seal failed for packet %d: %v", pn, err))
	}
	return append(dst, ct...)
}

func (s *gmLongSealer) EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	applyGMHeaderMask(s.km.hp, s.isLong, sample, firstByte, pnBytes)
}

func (s *gmLongSealer) Overhead() int { return s.km.aead.Overhead() }

// gmLongOpener implements LongHeaderOpener for Initial and Handshake packets.
type gmLongOpener struct {
	km            *gmKeyMaterial
	isLong        bool
	highestRcvdPN protocol.PacketNumber
}

func (o *gmLongOpener) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	applyGMHeaderMask(o.km.hp, o.isLong, sample, firstByte, pnBytes) // XOR is self-inverse
}

func (o *gmLongOpener) DecodePacketNumber(wirePN protocol.PacketNumber, wirePNLen protocol.PacketNumberLen) protocol.PacketNumber {
	return protocol.DecodePacketNumber(wirePNLen, o.highestRcvdPN, wirePN)
}

func (o *gmLongOpener) Open(dst, src []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error) {
	pt, err := o.km.aead.Open(uint64(pn), src, ad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	if pn > o.highestRcvdPN {
		o.highestRcvdPN = pn
	}
	return append(dst, pt...), nil
}

// --- Short header (1-RTT) ---

// gmShortSealer implements ShortHeaderSealer for 1-RTT packets. KeyPhase() is
// fixed at construction (P0: no key update; P3 wires tls13gm.QUICKeyUpdate into
// a rollKeys method).
type gmShortSealer struct {
	gmLongSealer
	kp protocol.KeyPhaseBit
}

func (s *gmShortSealer) KeyPhase() protocol.KeyPhaseBit { return s.kp }

// gmShortOpener implements ShortHeaderOpener for 1-RTT packets.
type gmShortOpener struct {
	km            *gmKeyMaterial
	highestRcvdPN protocol.PacketNumber
	kp            protocol.KeyPhaseBit
}

func (o *gmShortOpener) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	applyGMHeaderMask(o.km.hp, false, sample, firstByte, pnBytes)
}

func (o *gmShortOpener) DecodePacketNumber(wirePN protocol.PacketNumber, wirePNLen protocol.PacketNumberLen) protocol.PacketNumber {
	return protocol.DecodePacketNumber(wirePNLen, o.highestRcvdPN, wirePN)
}

func (o *gmShortOpener) Open(dst, src []byte, _ monotime.Time, pn protocol.PacketNumber, kp protocol.KeyPhaseBit, ad []byte) ([]byte, error) {
	if kp != o.kp {
		// P0: fixed key phase. A mismatch means the peer initiated a key
		// update we do not yet handle; reject rather than decrypt with stale
		// keys. P3 adds rollKeys support.
		return nil, ErrKeysNotYetAvailable
	}
	pt, err := o.km.aead.Open(uint64(pn), src, ad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	if pn > o.highestRcvdPN {
		o.highestRcvdPN = pn
	}
	return append(dst, pt...), nil
}

// --- Constructors (used by GMCryptoSetup in P0d) ---

// newGMLongSealer builds a LongHeaderSealer for Initial or Handshake packets.
func newGMLongSealer(keys *tls13gm.QUICPacketKeys) (*gmLongSealer, error) {
	km, err := newGMKeyMaterial(keys)
	if err != nil {
		return nil, err
	}
	return &gmLongSealer{km: km, isLong: true}, nil
}

// newGMLongOpener builds a LongHeaderOpener for Initial or Handshake packets.
func newGMLongOpener(keys *tls13gm.QUICPacketKeys) (*gmLongOpener, error) {
	km, err := newGMKeyMaterial(keys)
	if err != nil {
		return nil, err
	}
	return &gmLongOpener{km: km, isLong: true}, nil
}

// newGMShortSealer builds a ShortHeaderSealer for 1-RTT packets.
func newGMShortSealer(keys *tls13gm.QUICPacketKeys, kp protocol.KeyPhaseBit) (*gmShortSealer, error) {
	km, err := newGMKeyMaterial(keys)
	if err != nil {
		return nil, err
	}
	return &gmShortSealer{gmLongSealer: gmLongSealer{km: km, isLong: false}, kp: kp}, nil
}

// newGMShortOpener builds a ShortHeaderOpener for 1-RTT packets.
func newGMShortOpener(keys *tls13gm.QUICPacketKeys, kp protocol.KeyPhaseBit) (*gmShortOpener, error) {
	km, err := newGMKeyMaterial(keys)
	if err != nil {
		return nil, err
	}
	return &gmShortOpener{km: km, kp: kp}, nil
}
