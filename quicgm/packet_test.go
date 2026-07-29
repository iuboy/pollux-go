package quicgm

import (
	"bytes"
	"testing"

	"github.com/iuboy/pollux-go/tls13gm"
)

func testSecret() []byte {
	return bytes.Repeat([]byte{0x42}, 32)
}

func mustNewProtector(t *testing.T) *QUICPacketProtector {
	t.Helper()
	p, err := NewQUICPacketProtector(testSecret())
	if err != nil {
		t.Fatalf("NewQUICPacketProtector: %v", err)
	}
	return p
}

func TestNewQUICPacketProtector_KeyLengths(t *testing.T) {
	p := mustNewProtector(t)
	defer p.Zero()
	k := p.Keys()
	if len(k.AEADKey) != 16 {
		t.Errorf("AEADKey: got %d bytes, want 16", len(k.AEADKey))
	}
	if len(k.AEADIV) != 12 {
		t.Errorf("AEADIV: got %d bytes, want 12", len(k.AEADIV))
	}
	if len(k.HeaderKey) != 16 {
		t.Errorf("HeaderKey: got %d bytes, want 16", len(k.HeaderKey))
	}
}

func TestNewQUICPacketProtector_Deterministic(t *testing.T) {
	p1, _ := NewQUICPacketProtector(testSecret())
	p2, _ := NewQUICPacketProtector(testSecret())
	defer p1.Zero()
	defer p2.Zero()
	if !bytes.Equal(p1.Keys().AEADKey, p2.Keys().AEADKey) {
		t.Error("same secret should derive the same AEAD key")
	}
}

func TestPayloadRoundTrip(t *testing.T) {
	p := mustNewProtector(t)
	defer p.Zero()
	header := []byte("quic-header")
	payload := []byte("the quick brown fox")
	for _, pn := range []uint64{0, 1, 0x1234, 0xDEADBEEF} {
		ct, err := p.EncryptPayload(pn, header, payload)
		if err != nil {
			t.Fatalf("EncryptPayload pn=%d: %v", pn, err)
		}
		pt, err := p.DecryptPayload(pn, header, ct)
		if err != nil {
			t.Fatalf("DecryptPayload pn=%d: %v", pn, err)
		}
		if !bytes.Equal(pt, payload) {
			t.Errorf("pn=%d roundtrip mismatch", pn)
		}
	}
}

func TestPayloadTamperRejected(t *testing.T) {
	p := mustNewProtector(t)
	defer p.Zero()
	ct, _ := p.EncryptPayload(1, []byte("h"), []byte("secret"))
	ct[0] ^= 0xff
	if _, err := p.DecryptPayload(1, []byte("h"), ct); err == nil {
		t.Error("tampered ciphertext should fail")
	}
}

func TestPayloadAADTamperRejected(t *testing.T) {
	p := mustNewProtector(t)
	defer p.Zero()
	ct, _ := p.EncryptPayload(1, []byte("header-a"), []byte("secret"))
	if _, err := p.DecryptPayload(1, []byte("header-b"), ct); err == nil {
		t.Error("tampered AAD should fail")
	}
}

func TestPayloadWrongPNRejected(t *testing.T) {
	p := mustNewProtector(t)
	defer p.Zero()
	ct, _ := p.EncryptPayload(1, []byte("h"), []byte("secret"))
	if _, err := p.DecryptPayload(2, []byte("h"), ct); err == nil {
		t.Error("wrong packet number should fail")
	}
}

func TestPayloadDifferentProtectors(t *testing.T) {
	p1, _ := NewQUICPacketProtector(testSecret())
	defer p1.Zero()
	p2, _ := NewQUICPacketProtector(bytes.Repeat([]byte{0x99}, 32))
	defer p2.Zero()
	ct, _ := p1.EncryptPayload(1, []byte("h"), []byte("secret"))
	if _, err := p2.DecryptPayload(1, []byte("h"), ct); err == nil {
		t.Error("decrypt with a different protector should fail")
	}
}

// buildPacketBuffer constructs a QUIC-like packet buffer for header-protection
// tests. firstByte encodes the packet number length in its low 2 bits; the
// packet number field is placed at pnOffset; the buffer is pnOffset+20 bytes
// long so the header-protection sample region is fully populated.
func buildPacketBuffer(firstByte byte, pnOffset int, pn uint64) []byte {
	buf := make([]byte, pnOffset+20)
	for i := range buf {
		buf[i] = byte(0xA0 + i%16)
	}
	buf[0] = firstByte
	pnLen := int(firstByte&0x03) + 1
	for i := pnLen - 1; i >= 0; i-- {
		buf[pnOffset+i] = byte(pn)
		pn >>= 8
	}
	return buf
}

func TestHeaderProtectionRoundTrip_LongHeader(t *testing.T) {
	p := mustNewProtector(t)
	defer p.Zero()
	const pnOffset = 4
	const pn uint64 = 0x1234
	// 0xC1: long header (form=11), pnLen-1 = 1 in low 2 bits → pnLen = 2.
	original := buildPacketBuffer(0xC1, pnOffset, pn)
	buf := append([]byte(nil), original...)

	if err := p.ApplyHeaderProtection(buf, pnOffset, 2, true); err != nil {
		t.Fatalf("ApplyHeaderProtection: %v", err)
	}
	if bytes.Equal(buf, original) {
		t.Fatal("ApplyHeaderProtection did not alter the buffer")
	}

	gotPN, err := p.RemoveHeaderProtection(buf, pnOffset, true)
	if err != nil {
		t.Fatalf("RemoveHeaderProtection: %v", err)
	}
	if gotPN != pn {
		t.Errorf("recovered packet number: got %d, want %d", gotPN, pn)
	}
	if !bytes.Equal(buf, original) {
		t.Errorf("remove did not restore the buffer:\ngot  %x\nwant %x", buf, original)
	}
}

func TestHeaderProtectionRoundTrip_ShortHeader(t *testing.T) {
	p := mustNewProtector(t)
	defer p.Zero()
	const pnOffset = 2
	const pn uint64 = 0x05
	// 0x41: short header (form=0), pnLen-1 = 1 in low 2 bits → pnLen = 2.
	original := buildPacketBuffer(0x41, pnOffset, pn)
	buf := append([]byte(nil), original...)

	if err := p.ApplyHeaderProtection(buf, pnOffset, 2, false); err != nil {
		t.Fatalf("ApplyHeaderProtection: %v", err)
	}
	gotPN, err := p.RemoveHeaderProtection(buf, pnOffset, false)
	if err != nil {
		t.Fatalf("RemoveHeaderProtection: %v", err)
	}
	if gotPN != pn {
		t.Errorf("recovered packet number: got %d, want %d", gotPN, pn)
	}
	if !bytes.Equal(buf, original) {
		t.Errorf("remove did not restore the buffer:\ngot  %x\nwant %x", buf, original)
	}
}

func TestApplyHeaderProtection_InvalidArgs(t *testing.T) {
	p := mustNewProtector(t)
	defer p.Zero()
	buf := make([]byte, 40)
	cases := []struct {
		name            string
		pnOffset, pnLen int
	}{
		{"offset zero", 0, 2},
		{"pnLen too small", 4, 0},
		{"pnLen too large", 4, 5},
		{"field exceeds buffer", 38, 4},
	}
	for _, c := range cases {
		if err := p.ApplyHeaderProtection(buf, c.pnOffset, c.pnLen, true); err == nil {
			t.Errorf("ApplyHeaderProtection(%s) should fail", c.name)
		}
	}
}

func TestRemoveHeaderProtection_BufferTooShort(t *testing.T) {
	p := mustNewProtector(t)
	defer p.Zero()
	buf := make([]byte, 10) // too short for sample at pnOffset=4 (needs 24)
	if _, err := p.RemoveHeaderProtection(buf, 4, true); err == nil {
		t.Error("short buffer should fail")
	}
}

func TestKeyUpdate(t *testing.T) {
	secret := testSecret()
	next, err := tls13gm.QUICKeyUpdate(secret)
	if err != nil {
		t.Fatalf("QUICKeyUpdate: %v", err)
	}
	if bytes.Equal(next, secret) {
		t.Error("key update should produce a different secret")
	}
	p1, _ := NewQUICPacketProtector(secret)
	defer p1.Zero()
	p2, _ := NewQUICPacketProtector(next)
	defer p2.Zero()
	if bytes.Equal(p1.Keys().AEADKey, p2.Keys().AEADKey) {
		t.Error("updated secret should derive different keys")
	}
}

func TestZero(t *testing.T) {
	p, _ := NewQUICPacketProtector(testSecret())
	p.Zero()
	k := p.Keys()
	if k.AEADKey != nil || k.AEADIV != nil || k.HeaderKey != nil {
		t.Error("Zero should nil out all key material")
	}
}

// TestZeroedProtectorDoesNotPanic is a regression test for a nil-pointer panic
// after Zero(): Zero() drops p.aead/p.hpBlock, so any subsequent public method
// used to dereference them and panic. Each method must now return a distinct
// error (errZeroedProtector) instead. TagSize stays usable (returns the fixed
// SM4-GCM constant) since it must not depend on the live AEAD.
func TestZeroedProtectorDoesNotPanic(t *testing.T) {
	p, _ := NewQUICPacketProtector(testSecret())
	p.Zero()

	if got := p.TagSize(); got != sm4GCMTagSize {
		t.Errorf("TagSize() after Zero = %d, want %d (fixed constant)", got, sm4GCMTagSize)
	}

	// None of these must panic; each must return an error.
	checkErr := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s after Zero: expected error, got nil", name)
		}
	}
	checkErr("EncryptPayload", wrapErr2(p.EncryptPayload(1, []byte("h"), []byte("p"))))
	checkErr("DecryptPayload", wrapErr2(p.DecryptPayload(1, []byte("h"), []byte("p"))))
	buf := buildPacketBuffer(0xC3, 6, 1)
	checkErr("ApplyHeaderProtection", p.ApplyHeaderProtection(buf, 6, 4, true))
	_, err := p.RemoveHeaderProtection(buf, 6, true)
	checkErr("RemoveHeaderProtection", err)
}

// wrapErr2 adapts the (_, error) return shape so checkErr can test for an error.
func wrapErr2(_ any, err error) error { return err }

// TestKeys_ReturnsIndependentCopy is a regression test for the aliasing race:
// Keys() previously returned the protector's internal *QUICPacketKeys pointer,
// so a caller mutating the returned slices (or a concurrent Zero()) would
// corrupt the protector's state. With the deep-copy fix the returned keys are
// independent — mutating them must not affect the protector, and Zero()'ing the
// copy must not affect the protector's keys either.
func TestKeys_ReturnsIndependentCopy(t *testing.T) {
	p := mustNewProtector(t)
	defer p.Zero()

	orig := p.Keys()
	if orig == nil || len(orig.AEADKey) != 16 {
		t.Fatalf("Keys() = %+v, want non-nil 16-byte AEADKey", orig)
	}

	// Snapshot the protector's view for later comparison.
	snap := p.Keys()

	// Mutate the returned copy — the protector must be unaffected.
	for i := range orig.AEADKey {
		orig.AEADKey[i] ^= 0xFF
	}
	orig.AEADIV[0] ^= 0xFF
	orig.HeaderKey[0] ^= 0xFF

	after := p.Keys()
	if !bytes.Equal(after.AEADKey, snap.AEADKey) || !bytes.Equal(after.AEADIV, snap.AEADIV) || !bytes.Equal(after.HeaderKey, snap.HeaderKey) {
		t.Error("mutating Keys() copy corrupted the protector's internal keys (alias bug)")
	}
}

