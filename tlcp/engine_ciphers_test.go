package tlcp

import (
	"bytes"
	"testing"
)

// TestTLCP_LookupCipherSuite verifies all four suite IDs resolve and report
// the correct material lengths.
func TestTLCP_LookupCipherSuite(t *testing.T) {
	cases := []struct {
		id                       uint16
		wantKey, wantMAC, wantIV int
		wantAEAD                 bool
	}{
		{SuiteECC_SM2_SM4_GCM_SM3, 16, 0, 4, true},
		{SuiteECC_SM2_SM4_CBC_SM3, 16, 32, 16, false},
		{SuiteECDHE_SM2_SM4_GCM_SM3, 16, 0, 4, true},
		{SuiteECDHE_SM2_SM4_CBC_SM3, 16, 32, 16, false},
	}
	for _, c := range cases {
		s := tlcpLookupCipherSuite(c.id)
		if s == nil {
			t.Errorf("suite %04x: not found", c.id)
			continue
		}
		if s.keyLen != c.wantKey || s.macLen != c.wantMAC || s.ivLen != c.wantIV {
			t.Errorf("suite %04x: lengths = key %d mac %d iv %d; want key %d mac %d iv %d",
				c.id, s.keyLen, s.macLen, s.ivLen, c.wantKey, c.wantMAC, c.wantIV)
		}
		if s.isAEAD() != c.wantAEAD {
			t.Errorf("suite %04x: isAEAD = %v, want %v", c.id, s.isAEAD(), c.wantAEAD)
		}
	}
	if tlcpLookupCipherSuite(0x1234) != nil {
		t.Error("unknown suite should resolve to nil")
	}
}

// TestTLCP_MutualCipherSuite verifies preference-ordered selection against peer
// IDs.
func TestTLCP_MutualCipherSuite(t *testing.T) {
	pref := []uint16{SuiteECC_SM2_SM4_GCM_SM3, SuiteECC_SM2_SM4_CBC_SM3}

	// Peer offers the GCM suite → first preference wins.
	s := tlcpMutualCipherSuite(pref, []uint16{SuiteECC_SM2_SM4_GCM_SM3})
	if s == nil || s.id != SuiteECC_SM2_SM4_GCM_SM3 {
		t.Error("expected ECC GCM selection")
	}
	// Peer offers only CBC → second preference.
	s = tlcpMutualCipherSuite(pref, []uint16{SuiteECC_SM2_SM4_CBC_SM3})
	if s == nil || s.id != SuiteECC_SM2_SM4_CBC_SM3 {
		t.Error("expected ECC CBC selection")
	}
	// No overlap → nil.
	if tlcpMutualCipherSuite(pref, []uint16{0x9999}) != nil {
		t.Error("expected nil for disjoint suites")
	}
}

// TestTLCP_CBC_RoundTrip verifies SM4-CBC encrypt/decrypt round-trips and that
// the encrypter/decrypter agree on block size.
func TestTLCP_CBC_RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16)
	iv := bytes.Repeat([]byte{0x02}, 16)

	enc, err := newTLCPCBCEncrypter(key, iv)
	if err != nil {
		t.Fatalf("newTLCPCBCEncrypter: %v", err)
	}
	dec, err := newTLCPCBCDecrypter(key, iv)
	if err != nil {
		t.Fatalf("newTLCPCBCDecrypter: %v", err)
	}
	if enc.BlockSize() != 16 || dec.BlockSize() != 16 {
		t.Errorf("CBC block size: enc=%d dec=%d, want 16", enc.BlockSize(), dec.BlockSize())
	}

	// Two blocks of plaintext (CBC requires block-aligned input).
	plaintext := []byte("sixteen-byte msg") // 16 bytes
	ct := make([]byte, len(plaintext))
	enc.CryptBlocks(ct, plaintext)

	pt := make([]byte, len(ct))
	dec.CryptBlocks(pt, ct)
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("CBC round-trip mismatch:\n got %x\n want %x", pt, plaintext)
	}
}

// TestTLCP_PrefixNonceAEAD_RoundTrip verifies the SM4-GCM prefix-nonce AEAD
// round-trips when the implicit prefix + explicit nonce are fed consistently.
func TestTLCP_PrefixNonceAEAD_RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x07}, 16)
	implicit := bytes.Repeat([]byte{0x08}, 4) // implicit nonce prefix

	a, err := newTLCPAEADSM4GCM(key, implicit)
	if err != nil {
		t.Fatalf("newTLCPAEADSM4GCM: %v", err)
	}
	if a.ExplicitNonceSize() != 8 {
		t.Errorf("explicit nonce size = %d, want 8", a.ExplicitNonceSize())
	}

	aad := []byte("record-header")
	plaintext := []byte("the quick brown fox")
	explicitNonce := bytes.Repeat([]byte{0x09}, 8)

	sealed := a.Seal(nil, explicitNonce, plaintext, aad)
	if len(sealed) != len(plaintext)+a.Overhead() {
		t.Errorf("sealed length = %d, want %d", len(sealed), len(plaintext)+a.Overhead())
	}

	got, err := a.Open(nil, explicitNonce, sealed, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("AEAD round-trip mismatch:\n got %x\n want %x", got, plaintext)
	}
}

// TestTLCP_PrefixNonceAEAD_TamperRejection verifies GCM authentication: a
// flipped ciphertext bit must fail Open.
func TestTLCP_PrefixNonceAEAD_TamperRejection(t *testing.T) {
	key := bytes.Repeat([]byte{0x07}, 16)
	implicit := bytes.Repeat([]byte{0x08}, 4)
	a, _ := newTLCPAEADSM4GCM(key, implicit)

	aad := []byte("hdr")
	plaintext := []byte("secret")
	nonce := bytes.Repeat([]byte{0x09}, 8)
	sealed := a.Seal(nil, nonce, plaintext, aad)

	sealed[0] ^= 0xFF // tamper
	if _, err := a.Open(nil, nonce, sealed, aad); err == nil {
		t.Error("Open succeeded on tampered ciphertext; want auth failure")
	}
}

// TestTLCP_PrefixNonceAEAD_WrongNonce verifies that a different explicit nonce
// does not decrypt the record (nonce is part of the AEAD input).
func TestTLCP_PrefixNonceAEAD_WrongNonce(t *testing.T) {
	key := bytes.Repeat([]byte{0x07}, 16)
	implicit := bytes.Repeat([]byte{0x08}, 4)
	a, _ := newTLCPAEADSM4GCM(key, implicit)

	sealed := a.Seal(nil, bytes.Repeat([]byte{0x09}, 8), []byte("payload"), nil)
	wrong := bytes.Repeat([]byte{0x0A}, 8)
	if _, err := a.Open(nil, wrong, sealed, nil); err == nil {
		t.Error("Open succeeded with wrong nonce; want auth failure")
	}
}

// TestTLCP_PrefixNonceAEAD_RejectsBadImplicitLength verifies the constructor
// enforces the 4-byte implicit-nonce contract.
func TestTLCP_PrefixNonceAEAD_RejectsBadImplicitLength(t *testing.T) {
	key := bytes.Repeat([]byte{0x07}, 16)
	if _, err := newTLCPAEADSM4GCM(key, bytes.Repeat([]byte{0x08}, 3)); err == nil {
		t.Error("expected error for 3-byte implicit nonce")
	}
	if _, err := newTLCPAEADSM4GCM(key, bytes.Repeat([]byte{0x08}, 5)); err == nil {
		t.Error("expected error for 5-byte implicit nonce")
	}
}

// TestTLCP_RecordMAC verifies the MAC covers seq + header + payload and is
// deterministic for identical inputs.
func TestTLCP_RecordMAC(t *testing.T) {
	key := bytes.Repeat([]byte{0x0B}, 32)
	h := tlcpHMACSM3(key)

	seq := []byte{0, 0, 0, 0, 0, 0, 0, 1}
	header := []byte{0x16, 0x01, 0x01, 0x00, 0x10}
	payload := []byte("payload-bytes!!")

	mac1 := tlcpRecordMAC(h, nil, seq, header, payload)
	if len(mac1) != 32 {
		t.Errorf("HMAC-SM3 output length = %d, want 32", len(mac1))
	}

	// Recompute with a fresh hash → identical.
	mac2 := tlcpRecordMAC(tlcpHMACSM3(key), nil, seq, header, payload)
	if !bytes.Equal(mac1, mac2) {
		t.Error("record MAC not deterministic")
	}

	// Different sequence number → different MAC.
	mac3 := tlcpRecordMAC(tlcpHMACSM3(key), nil, []byte{0, 0, 0, 0, 0, 0, 0, 2}, header, payload)
	if bytes.Equal(mac1, mac3) {
		t.Error("record MAC did not change with sequence number")
	}
}
