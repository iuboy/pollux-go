package test

import (
	"bytes"
	"testing"

	polluxQUICGM "github.com/iuboy/pollux-go/quicgm"
	"github.com/iuboy/pollux-go/tls13gm"
)

func blackboxSecret() []byte { return bytes.Repeat([]byte{0x55}, 32) }

func TestBlackBox_QUICGM_PayloadRoundTrip(t *testing.T) {
	protector, err := polluxQUICGM.NewQUICPacketProtector(blackboxSecret())
	if err != nil {
		t.Fatalf("NewQUICPacketProtector: %v", err)
	}
	defer protector.Zero()

	header := []byte("long-header-bytes")
	payload := []byte("quicgm transport black-box payload")
	ct, err := protector.EncryptPayload(42, header, payload)
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}
	if len(ct) != len(payload)+16 {
		t.Errorf("ciphertext length: got %d, want %d (payload + 16-byte tag)", len(ct), len(payload)+16)
	}

	pt, err := protector.DecryptPayload(42, header, ct)
	if err != nil {
		t.Fatalf("DecryptPayload: %v", err)
	}
	if !bytes.Equal(pt, payload) {
		t.Errorf("roundtrip: got %q, want %q", pt, payload)
	}
}

func TestBlackBox_QUICGM_HeaderProtectionRoundTrip(t *testing.T) {
	protector, err := polluxQUICGM.NewQUICPacketProtector(blackboxSecret())
	if err != nil {
		t.Fatalf("NewQUICPacketProtector: %v", err)
	}
	defer protector.Zero()

	// long-header packet buffer with a 2-byte packet number at offset 4
	original := make([]byte, 24)
	for i := range original {
		original[i] = byte(0xB0 + i%16)
	}
	original[0] = 0xC1 // long header, pnLen = 2
	original[4] = 0x12
	original[5] = 0x34

	buf := append([]byte(nil), original...)
	if err := protector.ApplyHeaderProtection(buf, 4, 2, true); err != nil {
		t.Fatalf("ApplyHeaderProtection: %v", err)
	}

	gotPN, err := protector.RemoveHeaderProtection(buf, 4, true)
	if err != nil {
		t.Fatalf("RemoveHeaderProtection: %v", err)
	}
	if gotPN != 0x1234 {
		t.Errorf("recovered packet number: got %d, want %d", gotPN, 0x1234)
	}
	if !bytes.Equal(buf, original) {
		t.Error("header protection is not invertible")
	}
}

func TestBlackBox_QUICGM_KeyUpdateRotatesKeys(t *testing.T) {
	secret := blackboxSecret()
	next, err := tls13gm.QUICKeyUpdate(secret)
	if err != nil {
		t.Fatalf("QUICKeyUpdate: %v", err)
	}

	p1, err := polluxQUICGM.NewQUICPacketProtector(secret)
	if err != nil {
		t.Fatal(err)
	}
	defer p1.Zero()
	p2, err := polluxQUICGM.NewQUICPacketProtector(next)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Zero()

	if bytes.Equal(p1.Keys().AEADKey, p2.Keys().AEADKey) {
		t.Error("key update should rotate the AEAD key")
	}

	// a packet encrypted under the old keys must not decrypt under the new keys
	ct, _ := p1.EncryptPayload(1, []byte("h"), []byte("payload"))
	if _, err := p2.DecryptPayload(1, []byte("h"), ct); err == nil {
		t.Error("old-key ciphertext should not decrypt under updated keys")
	}
}

func TestBlackBox_QUICGM_PayloadTamperRejected(t *testing.T) {
	protector, _ := polluxQUICGM.NewQUICPacketProtector(blackboxSecret())
	defer protector.Zero()
	ct, _ := protector.EncryptPayload(7, []byte("h"), []byte("payload"))
	ct[0] ^= 0xff
	if _, err := protector.DecryptPayload(7, []byte("h"), ct); err == nil {
		t.Error("tampered ciphertext should be rejected")
	}
}
