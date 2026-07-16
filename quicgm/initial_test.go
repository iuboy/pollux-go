package quicgm

import (
	"bytes"
	"strings"
	"testing"
)

func mustSeal(t *testing.T, dcid, scid, token []byte, pn uint64, payload []byte) []byte {
	t.Helper()
	pkt, err := SealInitialPacket(dcid, scid, token, pn, payload)
	if err != nil {
		t.Fatalf("SealInitialPacket: %v", err)
	}
	return pkt
}

func TestInitialPacket_RoundTrip(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	scid := []byte{0x01, 0x02, 0x03, 0x04}
	token := []byte("initial-token")
	payload := bytes.Repeat([]byte("payload-"), 4) // 32 bytes, enough for HP sample

	for _, pn := range []uint64{0, 1, 0x2A, 0x1234, 0xDEADBEEF} {
		pkt := mustSeal(t, dcid, scid, token, pn, payload)
		version, gotSCID, gotToken, gotPN, gotPayload, err := OpenInitialPacket(dcid, pkt)
		if err != nil {
			t.Fatalf("OpenInitialPacket(pn=%d): %v", pn, err)
		}
		if version != QUICVersion1 {
			t.Errorf("version: got %#x, want %#x", version, QUICVersion1)
		}
		if !bytes.Equal(gotSCID, scid) {
			t.Errorf("scid: got %x, want %x", gotSCID, scid)
		}
		if !bytes.Equal(gotToken, token) {
			t.Errorf("token: got %x, want %x", gotToken, token)
		}
		if gotPN != pn {
			t.Errorf("pn: got %d, want %d", gotPN, pn)
		}
		if !bytes.Equal(gotPayload, payload) {
			t.Errorf("payload mismatch for pn=%d", pn)
		}
	}
}

func TestInitialPacket_HeaderFormSet(t *testing.T) {
	pkt := mustSeal(t, []byte{1, 2, 3, 4}, []byte{5, 6}, nil, 0, bytes.Repeat([]byte{0}, 32))
	if pkt[0]&0x80 == 0 {
		t.Error("Initial packet must set long-header form bit")
	}
}

func TestInitialPacket_DifferentDCIDIsolated(t *testing.T) {
	payload := bytes.Repeat([]byte{0x77}, 32)
	pkt := mustSeal(t, []byte{0xAA, 0xBB, 0xCC, 0xDD}, []byte{1}, nil, 7, payload)
	// Opening with a different dcid derives different Initial keys -> AEAD fails.
	if _, _, _, _, _, err := OpenInitialPacket([]byte{0x11, 0x22, 0x33, 0x44}, pkt); err == nil {
		t.Error("opening with a different dcid should fail")
	}
}

func TestInitialPacket_TamperRejected(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	pkt := mustSeal(t, dcid, []byte{1, 2}, nil, 1, bytes.Repeat([]byte{0xAB}, 32))
	// Flip a byte in the AEAD ciphertext region (well past the header/pn).
	tampered := append([]byte(nil), pkt...)
	tampered[len(tampered)-1] ^= 0x01
	if _, _, _, _, _, err := OpenInitialPacket(dcid, tampered); err == nil {
		t.Error("tampered ciphertext should fail decryption")
	}
}

func TestInitialPacket_ShortHeaderRejected(t *testing.T) {
	// A 0 first byte (short header form) must be rejected by OpenInitialPacket.
	short := append([]byte{0x00}, bytes.Repeat([]byte{0}, 32)...)
	if _, _, _, _, _, err := OpenInitialPacket([]byte{1, 2, 3, 4}, short); err == nil {
		t.Error("short-header packet should be rejected")
	}
}

// TestInitialPacket_RejectsMissingFixedBit confirms OpenInitialPacket rejects a
// long-header byte whose Fixed Bit (0x40) is clear, per RFC 9000 §17.2.
func TestInitialPacket_RejectsMissingFixedBit(t *testing.T) {
	// 0x80 = long header, but Fixed Bit (0x40) NOT set. Fill the rest with
	// enough bytes so the version read doesn't trip first.
	noFixed := append([]byte{0x80}, bytes.Repeat([]byte{0}, 32)...)
	if _, _, _, _, _, err := OpenInitialPacket([]byte{1, 2, 3, 4}, noFixed); err == nil {
		t.Error("packet without Fixed Bit set should be rejected")
	}
}

// TestInitialPacket_RejectsNonInitialType confirms OpenInitialPacket rejects a
// long-header byte whose type bits (5-4) are not 0b00 (Initial). 0x90 encodes
// type=0b01 (0-RTT-style), which is not an Initial packet.
func TestInitialPacket_RejectsNonInitialType(t *testing.T) {
	// 0xC0 = long header + Fixed Bit; 0x10 sets type bits to 0b01 (not Initial).
	notInitial := append([]byte{0xD0}, bytes.Repeat([]byte{0}, 32)...)
	if _, _, _, _, _, err := OpenInitialPacket([]byte{1, 2, 3, 4}, notInitial); err == nil {
		t.Error("non-Initial long-header packet should be rejected")
	}
}

// TestSealInitialPacket_RejectsEmptyDCIDUpFront 确认 SealInitialPacket 在密钥
// 派生之前就拒绝空 dcid（错误信息为 quicgm 层级，而非 HKDF 层级）。
//
// 回归背景：此前空 dcid 检查放在 DeriveQUICInitialSecrets 调用之后，是死代码
// （后者已校验空 dcid 并提前返回）。修复将检查前移，确保立即返回清晰的
// quicgm 错误并避免无谓的 HKDF 计算。
func TestSealInitialPacket_RejectsEmptyDCIDUpFront(t *testing.T) {
	_, err := SealInitialPacket(nil, []byte{1, 2}, nil, 1, []byte("payload"))
	if err == nil {
		t.Fatal("SealInitialPacket with empty dcid should fail")
	}
	if !strings.Contains(err.Error(), "dcid must be non-empty") {
		t.Errorf("expected quicgm-level empty dcid error, got: %v", err)
	}
}
