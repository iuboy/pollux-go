package tls13gm

import (
	"bytes"
	"testing"

	"github.com/iuboy/pollux-go/sm3"
)

func TestPreSharedKeyExtension_RoundTrip(t *testing.T) {
	identities := []PskIdentity{
		{Identity: bytes.Repeat([]byte{0xAB}, sm3.Size), ObfuscatedTicketAge: 0x11223344},
	}
	binders := [][]byte{bytes.Repeat([]byte{0xCD}, sm3.Size)}
	data, err := marshalPreSharedKeyExtension(identities, binders)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	gotIDs, gotBinders, err := parsePreSharedKeyExtension(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(gotIDs) != 1 || !bytes.Equal(gotIDs[0].Identity, identities[0].Identity) || gotIDs[0].ObfuscatedTicketAge != identities[0].ObfuscatedTicketAge {
		t.Fatalf("identity mismatch: %+v", gotIDs)
	}
	if len(gotBinders) != 1 || !bytes.Equal(gotBinders[0], binders[0]) {
		t.Fatalf("binder mismatch: %x", gotBinders)
	}
}

// TestPreSharedKeyExtension_TruncatedForm verifies that a nil/empty binders
// slice yields the truncated extension (binders list length 0) used to compute
// the binder over the ClientHello.
func TestPreSharedKeyExtension_TruncatedForm(t *testing.T) {
	identities := []PskIdentity{{Identity: []byte("psk"), ObfuscatedTicketAge: 1}}
	trunc, err := marshalPreSharedKeyExtension(identities, nil)
	if err != nil {
		t.Fatalf("marshal truncated: %v", err)
	}
	// The binders vector length is the last 2 bytes before an empty tail; with
	// no binders the encoded binders-vector length field must be 0.
	_, binders, err := parsePreSharedKeyExtension(trunc)
	if err != nil {
		t.Fatalf("parse truncated: %v", err)
	}
	if len(binders) != 0 {
		t.Fatalf("truncated form has %d binders, want 0", len(binders))
	}
}

func TestPSKKeyExchangeModes_RoundTrip(t *testing.T) {
	modes := []uint8{PSKKeyExchangeModeDHEKE}
	data := marshalPSKKeyExchangeModesExtension(modes)
	if len(data) != 2 || data[0] != 1 || data[1] != PSKKeyExchangeModeDHEKE {
		t.Fatalf("encoded psk_key_exchange_modes = %x, want [01 01]", data)
	}
}

func TestComputeResumptionBinder_Deterministic(t *testing.T) {
	psk := bytes.Repeat([]byte{0x42}, sm3.Size)
	trunc := []byte{0x01, 0x00, 0x00, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f} // mock handshake msg
	b1, err := computeResumptionBinder(psk, trunc)
	if err != nil {
		t.Fatalf("compute binder: %v", err)
	}
	b2, err := computeResumptionBinder(psk, trunc)
	if err != nil {
		t.Fatalf("compute binder again: %v", err)
	}
	if len(b1) != sm3.Size {
		t.Fatalf("binder length %d, want %d", len(b1), sm3.Size)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("binder not deterministic for identical inputs")
	}
	// Different PSK / different transcript must yield different binders.
	b3, _ := computeResumptionBinder(bytes.Repeat([]byte{0x43}, sm3.Size), trunc)
	if bytes.Equal(b1, b3) {
		t.Fatal("binder identical for different PSK")
	}
}

// TestDeriveEarlyTrafficKeys verifies the 0-RTT key derivation (RFC 8446 §7.1
// client_early_traffic_secret): deterministic for fixed PSK+transcript, and
// the PSK is mixed into the output.
func TestDeriveEarlyTrafficKeys(t *testing.T) {
	psk := bytes.Repeat([]byte{0x42}, sm3.Size)
	trHash := bytes.Repeat([]byte{0x11}, sm3.Size)

	keys1, err := DeriveEarlyTrafficKeys(psk, trHash)
	if err != nil {
		t.Fatalf("DeriveEarlyTrafficKeys: %v", err)
	}
	keys2, _ := DeriveEarlyTrafficKeys(psk, trHash)
	if !bytes.Equal(keys1.AEADKey, keys2.AEADKey) || !bytes.Equal(keys1.AEADIV, keys2.AEADIV) {
		t.Fatal("0-RTT keys not deterministic")
	}
	// Different PSK must yield different keys.
	keys3, _ := DeriveEarlyTrafficKeys(bytes.Repeat([]byte{0x43}, sm3.Size), trHash)
	if bytes.Equal(keys1.AEADKey, keys3.AEADKey) {
		t.Fatal("0-RTT keys identical for different PSK")
	}
	// Different transcript must yield different keys.
	keys4, _ := DeriveEarlyTrafficKeys(psk, bytes.Repeat([]byte{0x22}, sm3.Size))
	if bytes.Equal(keys1.AEADKey, keys4.AEADKey) {
		t.Fatal("0-RTT keys identical for different transcript")
	}
	// The derived keys must round-trip through the AEAD.
	aead, err := NewAEAD(keys1.AEADKey, keys1.AEADIV)
	if err != nil {
		t.Fatalf("NewAEAD: %v", err)
	}
	ct, _ := aead.Seal(1, []byte("0rtt"), []byte("hdr"))
	pt, err := aead.Open(1, ct, []byte("hdr"))
	if err != nil || string(pt) != "0rtt" {
		t.Fatalf("0-RTT AEAD round-trip: %v / %q", err, pt)
	}
}
