package handshake

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/iuboy/pollux-go/sm4"
	"github.com/iuboy/pollux-go/tls13gm"
	"github.com/quic-go/quic-go/internal/protocol"
)

// fixedGMSecret is a deterministic traffic secret used to derive identical
// QUICPacketKeys for the adapter and the reference computations.
func fixedGMSecret() []byte { return bytes.Repeat([]byte{0x42}, 32) }

// TestGMSealer_HeaderProtectionRoundTrip verifies the adapter's header
// protection is self-consistent: EncryptHeader then DecryptHeader (via the
// matching opener) recovers the original first byte and packet-number bytes.
// The mask is SM4-ECB over the 16-byte sample per RFC 9001 §5.4.3, with the low
// 4 bits (long header) or 5 bits (short header) of the first byte and the
// packet-number bytes XOR-ed — mirrored exactly by applyGMHeaderMask.
func TestGMSealer_HeaderProtectionRoundTrip(t *testing.T) {
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

	const pnLen = 4
	originalFirst := byte(0xC3)
	originalPN := make([]byte, pnLen)
	binary.BigEndian.PutUint32(originalPN, 0x11223344)
	sample := bytes.Repeat([]byte{0xAB}, 16)

	firstByte := originalFirst
	pnBytes := append([]byte(nil), originalPN...)
	sealer.EncryptHeader(sample, &firstByte, pnBytes)
	if firstByte == originalFirst {
		t.Fatal("EncryptHeader did not change the first byte")
	}

	// DecryptHeader is the XOR inverse with the same mask; it must recover the
	// originals so the unpacker can read the true packet number.
	opener.DecryptHeader(sample, &firstByte, pnBytes)
	if firstByte != originalFirst {
		t.Fatalf("first byte not restored: %#02x", firstByte)
	}
	if !bytes.Equal(pnBytes, originalPN) {
		t.Fatalf("packet number not restored: %x", pnBytes)
	}
}

// TestGMSealer_HeaderProtectionMatchesManualMask proves the adapter's
// EncryptHeader matches a hand-computed SM4-ECB mask (RFC 9001 §5.4.3). This is
// the same computation quicgm.QUICPacketProtector performs, so the two paths
// produce byte-identical header protection without this test importing quicgm
// (which would form a test import cycle through the fork's top-level package).
func TestGMSealer_HeaderProtectionMatchesManualMask(t *testing.T) {
	keys, err := tls13gm.DeriveQUICPacketKeys(fixedGMSecret())
	if err != nil {
		t.Fatalf("DeriveQUICPacketKeys: %v", err)
	}
	hpBlock, err := sm4.NewCipher(keys.HeaderKey)
	if err != nil {
		t.Fatalf("sm4.NewCipher: %v", err)
	}

	for _, tc := range []struct {
		name   string
		isLong bool
		first  byte
	}{
		{"long", true, 0xC3},
		{"short", false, 0x40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newGMShortSealerForTest(t, keys, tc.isLong)
			sample := bytes.Repeat([]byte{0x55}, 16)
			first := tc.first
			pn := []byte{0x11, 0x22, 0x33, 0x44}
			adapterFirst, adapterPN := first, append([]byte(nil), pn...)
			s.EncryptHeader(sample, &adapterFirst, adapterPN)

			// Manual mask: SM4-ECB(sample), then XOR per RFC 9001 §5.4.3.
			var mask [16]byte
			hpBlock.Encrypt(mask[:], sample)
			wantFirst := first
			if tc.isLong {
				wantFirst ^= mask[0] & 0x0f
			} else {
				wantFirst ^= mask[0] & 0x1f
			}
			wantPN := append([]byte(nil), pn...)
			for i := range wantPN {
				wantPN[i] ^= mask[1+i]
			}
			if adapterFirst != wantFirst {
				t.Fatalf("first byte: adapter %#02x, manual %#02x", adapterFirst, wantFirst)
			}
			if !bytes.Equal(adapterPN, wantPN) {
				t.Fatalf("pn bytes: adapter %x, manual %x", adapterPN, wantPN)
			}
		})
	}
}

// newGMShortSealerForTest builds a sealer with an explicit isLong flag for the
// header-protection mask test (long vs short header).
func newGMShortSealerForTest(t *testing.T, keys *tls13gm.QUICPacketKeys, isLong bool) *gmLongSealer {
	t.Helper()
	km, err := newGMKeyMaterial(keys)
	if err != nil {
		t.Fatalf("newGMKeyMaterial: %v", err)
	}
	return &gmLongSealer{km: km, isLong: isLong}
}

// TestGMSealer_PayloadSealMatchesTLS13AEAD confirms the adapter's Seal delegates
// to tls13gm.AEAD (same nonce scheme), producing identical ciphertext. Both
// quicgm and the adapter share this AEAD, so packets are byte-compatible.
func TestGMSealer_PayloadSealMatchesTLS13AEAD(t *testing.T) {
	keys, err := tls13gm.DeriveQUICPacketKeys(fixedGMSecret())
	if err != nil {
		t.Fatalf("DeriveQUICPacketKeys: %v", err)
	}
	sealer, err := newGMLongSealer(keys)
	if err != nil {
		t.Fatalf("newGMLongSealer: %v", err)
	}
	refAEAD, err := tls13gm.NewAEAD(keys.AEADKey, keys.AEADIV)
	if err != nil {
		t.Fatalf("tls13gm.NewAEAD: %v", err)
	}

	header := []byte{0xC3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02, 0x03, 0x04}
	payload := []byte("pollux-go GM QUIC payload")
	const pn uint64 = 42

	adapterCT := sealer.Seal(nil, payload, protocol.PacketNumber(pn), header)
	refCT, err := refAEAD.Seal(pn, payload, header)
	if err != nil {
		t.Fatalf("ref AEAD.Seal: %v", err)
	}
	if !bytes.Equal(adapterCT, refCT) {
		t.Fatalf("ciphertext mismatch:\n adapter %x\n ref     %x", adapterCT, refCT)
	}

	// Round-trip through the matching opener.
	opener, err := newGMLongOpener(keys)
	if err != nil {
		t.Fatalf("newGMLongOpener: %v", err)
	}
	pt, err := opener.Open(nil, adapterCT, protocol.PacketNumber(pn), header)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, payload) {
		t.Fatalf("round-trip plaintext mismatch: %q", pt)
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
	ct[len(ct)-1] ^= 0xff
	if _, err := opener.Open(nil, ct, 7, header); err != ErrDecryptionFailed {
		t.Fatalf("Open on tampered tag returned %v, want ErrDecryptionFailed", err)
	}
}
