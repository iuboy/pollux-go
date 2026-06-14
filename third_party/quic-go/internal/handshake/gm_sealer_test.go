package handshake

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/iuboy/pollux-go/quicgm"
	"github.com/iuboy/pollux-go/tls13gm"
	"github.com/quic-go/quic-go/internal/protocol"
)

// fixedGMSecret is a deterministic traffic secret used to derive identical
// QUICPacketKeys for both the adapter and the quicgm reference path.
func fixedGMSecret() []byte { return bytes.Repeat([]byte{0x42}, 32) }

// TestGMSealer_HeaderProtectionMatchesQuicgm proves the adapter's header
// protection (applyGMHeaderMask via EncryptHeader) produces byte-identical output
// to the standalone quicgm.QUICPacketProtector.ApplyHeaderProtection for the same
// keys, sample, and header bytes. This is the contract that lets quic-go packets
// sealed through GMCryptoSetup interoperate with the quicgm packet-protection
// reference implementation.
func TestGMSealer_HeaderProtectionMatchesQuicgm(t *testing.T) {
	keys, err := tls13gm.DeriveQUICPacketKeys(fixedGMSecret())
	if err != nil {
		t.Fatalf("DeriveQUICPacketKeys: %v", err)
	}
	sealer, err := newGMLongSealer(keys)
	if err != nil {
		t.Fatalf("newGMLongSealer: %v", err)
	}
	prot, err := quicgm.NewQUICPacketProtectorFromKeys(keys)
	if err != nil {
		t.Fatalf("NewQUICPacketProtectorFromKeys: %v", err)
	}

	// Build a long-header buffer: [firstByte][3 filler][4-byte pn][payload room for sample].
	const pnOffset, pnLen = 4, 4
	original := make([]byte, pnOffset+pnLen+16+8)
	original[0] = 0xC3 // long-header first byte
	binary.BigEndian.PutUint32(original[pnOffset:], 0x11223344)

	// quicgm path: applies HP in place over the whole buffer.
	quicgmBuf := append([]byte(nil), original...)
	if err := prot.ApplyHeaderProtection(quicgmBuf, pnOffset, pnLen, true); err != nil {
		t.Fatalf("quicgm ApplyHeaderProtection: %v", err)
	}

	// adapter path: the packer hands us the sample, firstByte pointer, and pn bytes
	// separately (quic-go's EncryptHeader signature). Extract them from the original.
	sample := append([]byte(nil), original[pnOffset+4:pnOffset+4+16]...)
	firstByte := original[0]
	pnBytes := append([]byte(nil), original[pnOffset:pnOffset+pnLen]...)
	sealer.EncryptHeader(sample, &firstByte, pnBytes)

	if firstByte != quicgmBuf[0] {
		t.Fatalf("first byte mismatch: adapter %#02x, quicgm %#02x", firstByte, quicgmBuf[0])
	}
	if !bytes.Equal(pnBytes, quicgmBuf[pnOffset:pnOffset+pnLen]) {
		t.Fatalf("packet-number bytes mismatch: adapter %x, quicgm %x", pnBytes, quicgmBuf[pnOffset:pnOffset+pnLen])
	}
}

// TestGMSealer_PayloadSealMatchesQuicgm proves the adapter's Seal produces the
// same ciphertext+tag as the quicgm reference for the same key, packet number,
// AAD, and plaintext. Both delegate to tls13gm.AEAD, so this guards against a
// future divergence in nonce construction.
func TestGMSealer_PayloadSealMatchesQuicgm(t *testing.T) {
	keys, err := tls13gm.DeriveQUICPacketKeys(fixedGMSecret())
	if err != nil {
		t.Fatalf("DeriveQUICPacketKeys: %v", err)
	}
	sealer, err := newGMLongSealer(keys)
	if err != nil {
		t.Fatalf("newGMLongSealer: %v", err)
	}
	prot, err := quicgm.NewQUICPacketProtectorFromKeys(keys)
	if err != nil {
		t.Fatalf("NewQUICPacketProtectorFromKeys: %v", err)
	}

	header := []byte{0xC3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02, 0x03, 0x04}
	payload := []byte("pollux-go GM QUIC payload")
	const pn uint64 = 42

	adapterCT := sealer.Seal(nil, payload, protocol.PacketNumber(pn), header)
	quicgmCT, err := prot.EncryptPayload(pn, header, payload)
	if err != nil {
		t.Fatalf("quicgm EncryptPayload: %v", err)
	}
	if !bytes.Equal(adapterCT, quicgmCT) {
		t.Fatalf("payload ciphertext mismatch:\n adapter %x\n quicgm  %x", adapterCT, quicgmCT)
	}

	// Round-trip: the matching opener must recover the plaintext.
	opener, err := newGMLongOpener(keys)
	if err != nil {
		t.Fatalf("newGMLongOpener: %v", err)
	}
	pt, err := opener.Open(nil, adapterCT, protocol.PacketNumber(pn), header)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, payload) {
		t.Fatalf("round-trip plaintext mismatch: got %q want %q", pt, payload)
	}
}

// TestGMSealer_RejectsTamperedTag confirms the opener returns ErrDecryptionFailed
// (not a raw AEAD error) on tag corruption, matching the quic-go contract.
func TestGMSealer_RejectsTamperedTag(t *testing.T) {
	keys, err := tls13gm.DeriveQUICPacketKeys(fixedGMSecret())
	if err != nil {
		t.Fatalf("DeriveQUICPacketKeys: %v", err)
	}
	sealer, err := newGMLongSealer(keys)
	if err != nil {
		t.Fatalf("newGMLongSealer: %v", err)
	}
	opener, err := newGMLongOpener(keys)
	if err != nil {
		t.Fatalf("newGMLongOpener: %v", err)
	}
	header := []byte{0xC3, 0x00, 0x00, 0x00, 0x01}
	ct := sealer.Seal(nil, []byte("x"), 7, header)
	ct[len(ct)-1] ^= 0xff // corrupt the GCM tag
	if _, err := opener.Open(nil, ct, 7, header); err != ErrDecryptionFailed {
		t.Fatalf("Open on tampered tag returned %v, want ErrDecryptionFailed", err)
	}
}
