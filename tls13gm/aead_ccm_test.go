package tls13gm

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestCCMAEAD_RFC8998_A2 verifies NewCCMAEAD against the SM4-CCM test vector
// from RFC 8998 Appendix A.2. Because the TLS 1.3 nonce is IV XOR seq_num and
// seq_num 0 leaves the IV unchanged, using the vector's nonce as the fixed IV
// with Seal(seqNum=0, ...) reproduces it exactly.
func TestCCMAEAD_RFC8998_A2(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00001234567800000000abcd")
	plaintext, _ := hex.DecodeString("aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa")
	ad, _ := hex.DecodeString("feedfacedeadbeeffeedfacedeadbeefabaddad2")
	want, _ := hex.DecodeString("48af93501fa62adbcd414cce6034d895dda1bf8f132f042098661572e7483094fd12e518ce062c98acee28d95df4416bed31a2f04476c18bb40c84a74b97dc5b16842d4fa186f56ab33256971fa110f4")

	a, err := NewCCMAEAD(key, iv)
	if err != nil {
		t.Fatalf("NewCCMAEAD: %v", err)
	}
	ct, err := a.Seal(0, plaintext, ad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !bytes.Equal(ct, want) {
		t.Fatalf("RFC 8998 A.2 mismatch:\n got %x\nwant %x", ct, want)
	}
	if a.Overhead() != 16 {
		t.Errorf("Overhead: got %d, want 16", a.Overhead())
	}

	// Round-trip: Open must recover the plaintext.
	pt, err := a.Open(0, ct, ad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round-trip plaintext mismatch")
	}
}

// TestCCMAEAD_RoundTrip exercises the seqNum-based nonce derivation across
// non-zero sequence numbers, tamper rejection, and AAD binding.
func TestCCMAEAD_RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 16)
	iv := bytes.Repeat([]byte{0x22}, 12)
	a, err := NewCCMAEAD(key, iv)
	if err != nil {
		t.Fatalf("NewCCMAEAD: %v", err)
	}
	pt := []byte("SM4-CCM protects TLS 1.3 records")
	aad := []byte("additional-data")

	for _, seq := range []uint64{0, 1, 42, 1<<32 + 7} {
		ct, err := a.Seal(seq, pt, aad)
		if err != nil {
			t.Fatalf("Seal(%d): %v", seq, err)
		}
		got, err := a.Open(seq, ct, aad)
		if err != nil {
			t.Fatalf("Open(%d): %v", seq, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("seq %d: plaintext mismatch", seq)
		}
		// A different sequence number must not decrypt (nonce mismatch).
		if _, err := a.Open(seq+1, ct, aad); err == nil {
			t.Fatalf("Open(%d) accepted ciphertext sealed under seq %d", seq+1, seq)
		}
	}

	// Tamper rejection.
	ct, _ := a.Seal(5, pt, aad)
	ct[len(ct)-1] ^= 0xFF
	if _, err := a.Open(5, ct, aad); err == nil {
		t.Fatal("Open accepted a tampered ciphertext")
	}

	// AAD binding: a changed AAD must fail authentication.
	ct, _ = a.Seal(5, pt, aad)
	if _, err := a.Open(5, ct, []byte("wrong-aad")); err == nil {
		t.Fatal("Open accepted ciphertext with wrong AAD")
	}
}
