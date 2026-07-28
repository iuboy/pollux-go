package quicgm

import (
	"bytes"
	"testing"

	"github.com/iuboy/pollux-go/tls13gm"
)

func TestCryptoFrame_RoundTrip(t *testing.T) {
	data := []byte("ClientHello...ServerHello...")
	var b []byte
	b, err := AppendCryptoFrame(b, 7, data)
	if err != nil {
		t.Fatal(err)
	}
	off, got, n, err := ReadCryptoFrame(b)
	if err != nil {
		t.Fatal(err)
	}
	if off != 7 {
		t.Errorf("offset: got %d, want 7", off)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("data mismatch")
	}
	if n != len(b) {
		t.Errorf("consumed: got %d, want %d", n, len(b))
	}
}

func TestCryptoFrame_HandlesTrailingFrame(t *testing.T) {
	// A packet may carry multiple frames; the parser reads exactly one CRYPTO
	// frame and reports how many bytes it consumed, leaving the rest.
	var b []byte
	b, _ = AppendCryptoFrame(b, 0, []byte{0x01})
	b = append(b, 0xFF) // start of a (here malformed) next frame
	_, _, n, err := ReadCryptoFrame(b)
	if err != nil {
		t.Fatalf("ReadCryptoFrame: %v", err)
	}
	if n >= len(b) {
		t.Fatalf("parser consumed all %d bytes; expected to leave trailing bytes", len(b))
	}
}

// deriveTwoLevels produces two distinct, non-empty key sets so packet tests can
// exercise isolation between encryption levels without running a full handshake.
func deriveTwoLevels(t *testing.T) (handshake, application *tls13gm.QUICPacketKeys) {
	t.Helper()
	hs, err := tls13gm.DeriveQUICPacketKeys([]byte("handshake-traffic-secret-0"))
	if err != nil {
		t.Fatal(err)
	}
	ap, err := tls13gm.DeriveQUICPacketKeys([]byte("application-traffic-secret-0"))
	if err != nil {
		t.Fatal(err)
	}
	return hs, ap
}

func TestHandshakePacket_RoundTrip(t *testing.T) {
	hs, _ := deriveTwoLevels(t)
	dcid := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	scid := []byte{0xCA, 0xFE}
	payload := []byte("handshake CRYPTO payload")

	packet, err := SealHandshakePacket(hs, dcid, scid, 42, payload)
	if err != nil {
		t.Fatalf("SealHandshakePacket: %v", err)
	}
	ver, gotSCID, pn, gotPayload, err := OpenHandshakePacket(hs, dcid, packet)
	if err != nil {
		t.Fatalf("OpenHandshakePacket: %v", err)
	}
	if ver != QUICVersion1 {
		t.Errorf("version: %x", ver)
	}
	if !bytes.Equal(gotSCID, scid) {
		t.Errorf("scid mismatch")
	}
	if pn != 42 {
		t.Errorf("pn: got %d, want 42", pn)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload mismatch")
	}
}

func TestHandshakePacket_RejectsTamper(t *testing.T) {
	hs, _ := deriveTwoLevels(t)
	packet, err := SealHandshakePacket(hs, []byte{1, 2}, []byte{3}, 1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	packet[len(packet)-1] ^= 0xFF
	if _, _, _, _, err := OpenHandshakePacket(hs, []byte{1, 2}, packet); err == nil {
		t.Fatal("OpenHandshakePacket accepted a tampered packet")
	}
}

// TestHandshakePacket_RejectsWrongLevel confirms a Handshake packet sealed with
// Handshake keys cannot be opened with Application keys (level isolation).
func TestHandshakePacket_RejectsWrongLevel(t *testing.T) {
	hs, ap := deriveTwoLevels(t)
	packet, err := SealHandshakePacket(hs, []byte{1, 2}, []byte{3}, 1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := OpenHandshakePacket(ap, []byte{1, 2}, packet); err == nil {
		t.Fatal("Handshake packet opened with Application keys (level isolation broken)")
	}
}

func Test1RTTPacket_RoundTrip(t *testing.T) {
	_, ap := deriveTwoLevels(t)
	dcid := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	payload := []byte("1-RTT STREAM payload")

	packet, err := Seal1RTTPacket(ap, dcid, 7, PacketNumberLen2, payload)
	if err != nil {
		t.Fatalf("Seal1RTTPacket: %v", err)
	}
	pn, gotPayload, err := Open1RTTPacket(ap, dcid, nil, packet)
	if err != nil {
		t.Fatalf("Open1RTTPacket: %v", err)
	}
	// With a 2-octet field the recovered wire value equals pn truncated to 16 bits.
	if pn != 7 {
		t.Errorf("pn: got %d, want 7", pn)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload mismatch")
	}
}

func Test1RTTPacket_RejectsTamper(t *testing.T) {
	_, ap := deriveTwoLevels(t)
	packet, err := Seal1RTTPacket(ap, []byte{1, 2, 3}, 1, PacketNumberLen1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	packet[len(packet)-1] ^= 0xFF
	if _, _, err := Open1RTTPacket(ap, []byte{1, 2, 3}, nil, packet); err == nil {
		t.Fatal("Open1RTTPacket accepted a tampered packet")
	}
}

func Test1RTTPacket_RejectsWrongLevel(t *testing.T) {
	hs, ap := deriveTwoLevels(t)
	packet, err := Seal1RTTPacket(ap, []byte{1, 2, 3}, 1, PacketNumberLen1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open1RTTPacket(hs, []byte{1, 2, 3}, nil, packet); err == nil {
		t.Fatal("1-RTT packet opened with Handshake keys (level isolation broken)")
	}
}

// Test1RTTPacket_PacketNumberReconstruction verifies the P1 fix: when the
// packet number is large enough to be truncated on the wire, the receiver must
// reconstruct the full value (via largestAcked) before AEAD decryption, because
// the SM4-GCM nonce is derived from the full packet number.
func Test1RTTPacket_PacketNumberReconstruction(t *testing.T) {
	_, ap := deriveTwoLevels(t)
	dcid := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	// pn=70000 truncated to 2 octets on the wire is 4464 (< 0x10000); without
	// reconstruction the AEAD nonce would be IV^4464 != IV^70000 and decryption
	// would fail.
	const pn uint64 = 70000
	largestAcked := uint64(69000)

	packet, err := Seal1RTTPacket(ap, dcid, pn, PacketNumberLen2, []byte("reconstructed"))
	if err != nil {
		t.Fatalf("Seal1RTTPacket: %v", err)
	}
	// Without reconstruction (nil largestAcked) the truncated nonce mismatches.
	// RemoveHeaderProtection mutates the buffer in place, so operate on a copy.
	nilPacket := append([]byte(nil), packet...)
	if _, _, err := Open1RTTPacket(ap, dcid, nil, nilPacket); err == nil {
		t.Fatal("Open1RTTPacket succeeded without reconstruction (nonce bug present)")
	}
	// With reconstruction against the right largestAcked it decrypts and recovers pn.
	gotPN, payload, err := Open1RTTPacket(ap, dcid, &largestAcked, packet)
	if err != nil {
		t.Fatalf("Open1RTTPacket with reconstruction: %v", err)
	}
	if gotPN != pn {
		t.Errorf("reconstructed pn: got %d, want %d", gotPN, pn)
	}
	if !bytes.Equal(payload, []byte("reconstructed")) {
		t.Error("payload mismatch")
	}
}
