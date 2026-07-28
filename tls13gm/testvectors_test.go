package tls13gm

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/iuboy/pollux-go/sm3"
)

// TestBuildHKDFLabelEncoding verifies that buildHKDFLabel produces the correct
// TLS 1.3 HkdfLabel wire encoding per RFC 8446 Section 7.1.
//
// The encoding format is:
//
//	struct {
//	    uint16 length;
//	    opaque label<7..255>;   // 1-byte length prefix + "tls13 " + label
//	    opaque context<0..255>; // 1-byte length prefix + context
//	} HkdfLabel;
//
// We verify against the RFC 8448 (Simple 1-RTT Handshake) HKDF-Expand-Label
// invocation for the "derived" label with an empty context and length=32.
// The encoded label bytes are algorithm-independent (same regardless of hash).
func TestBuildHKDFLabelEncoding(t *testing.T) {
	label, err := buildHKDFLabel("derived", nil, 32)
	if err != nil {
		t.Fatalf("buildHKDFLabel: %v", err)
	}

	// Expected layout:
	//   00 20                                      — length = 32
	//   0D                                         — label length = 13 (len("tls13 derived"))
	//   74 6c 73 31 33 20 64 65 72 69 76 65 64    — "tls13 derived"
	//   00                                         — context length = 0
	//
	// Total: 2 + 1 + 13 + 1 = 17 bytes

	if len(label) != 17 {
		t.Fatalf("label length: got %d, want 17", len(label))
	}

	// length field = 0x0020
	if label[0] != 0x00 || label[1] != 0x20 {
		t.Fatalf("length field: got %x, want 0020", label[0:2])
	}

	// label vector length = 13
	if label[2] != 13 {
		t.Fatalf("label vector length: got %d, want 13", label[2])
	}

	// label content = "tls13 derived"
	gotLabel := string(label[3 : 3+13])
	if gotLabel != "tls13 derived" {
		t.Fatalf("label content: got %q, want %q", gotLabel, "tls13 derived")
	}

	// context vector length = 0
	if label[16] != 0 {
		t.Fatalf("context vector length: got %d, want 0", label[16])
	}
}

// TestBuildHKDFLabelWithContext verifies buildHKDFLabel with a non-empty context.
func TestBuildHKDFLabelWithContext(t *testing.T) {
	ctx := []byte{0x01, 0x02, 0x03}
	label, err := buildHKDFLabel("key", ctx, 16)
	if err != nil {
		t.Fatalf("buildHKDFLabel: %v", err)
	}

	// length = 16 → 0x0010
	if label[0] != 0x00 || label[1] != 0x10 {
		t.Fatalf("length: got %x, want 0010", label[0:2])
	}

	// "tls13 key" = 9 bytes
	if label[2] != 9 {
		t.Fatalf("label vector length: got %d, want 9", label[2])
	}

	// context vector length = 3
	ctxLenOffset := 3 + 9
	if label[ctxLenOffset] != 3 {
		t.Fatalf("context vector length: got %d, want 3", label[ctxLenOffset])
	}

	// context bytes
	if !bytes.Equal(label[ctxLenOffset+1:], ctx) {
		t.Fatalf("context bytes: got %x, want %x", label[ctxLenOffset+1:], ctx)
	}
}

// TestHKDFExpandLabelDeterminism verifies that HKDFExpandLabel with SM3 is
// deterministic: same inputs always produce the same output, and the output
// has the requested length.
func TestHKDFExpandLabelDeterminism(t *testing.T) {
	secret := make([]byte, 32) // all-zero 32-byte secret

	out1, err := HKDFExpandLabel(secret, "key", nil, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(out1) != 16 {
		t.Fatalf("output length: got %d, want 16", len(out1))
	}

	out2, err := HKDFExpandLabel(secret, "key", nil, 16)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(out1, out2) {
		t.Fatalf("HKDFExpandLabel not deterministic:\n  first:  %x\n  second: %x", out1, out2)
	}
}

// TestHKDFExpandLabelLengths verifies that HKDFExpandLabel works for various
// output lengths and always returns exactly the requested number of bytes.
func TestHKDFExpandLabelLengths(t *testing.T) {
	secret := make([]byte, 32)

	for _, length := range []int{1, 16, 32, 48, 64} {
		out, err := HKDFExpandLabel(secret, "iv", nil, length)
		if err != nil {
			t.Fatalf("length=%d: %v", length, err)
		}
		if len(out) != length {
			t.Errorf("length=%d: got %d bytes, want %d", length, len(out), length)
		}
	}
}

// TestHKDFExpandLabelInvalidLength verifies that HKDFExpandLabel rejects
// invalid length values.
func TestHKDFExpandLabelInvalidLength(t *testing.T) {
	secret := make([]byte, 32)

	for _, length := range []int{0, -1, 65536} {
		_, err := HKDFExpandLabel(secret, "key", nil, length)
		if err == nil {
			t.Errorf("expected error for length=%d, got nil", length)
		}
	}
}

// TestKeyScheduleChain verifies the internal consistency of the full
// RFC 8446 Section 7.1 key schedule chain driven by SM3:
//
//	Early Secret → Derived Secret ("derived") → Handshake Secret
//	  → Derived Secret ("derived") → Master Secret
//
// Since RFC 8998 does not publish independent test vectors, we verify:
//  1. Determinism: the same inputs always produce the same outputs
//  2. Correct lengths: all secrets are 32 bytes (SM3 output size)
//  3. Non-trivial: secrets are not all-zero
//  4. Derivation chain consistency: re-deriving from the same inputs matches
func TestKeyScheduleChain(t *testing.T) {
	// Use a zero-length IKM for early secret (as in TLS 1.3 when no PSK)
	earlyIKM := make([]byte, 32) // all-zero

	// Early Secret = HKDF-Extract(salt=0^32, IKM)
	earlySecret := sm3.HKDFExtract(nil, earlyIKM)
	if len(earlySecret) != 32 {
		t.Fatalf("earlySecret length: got %d, want 32", len(earlySecret))
	}

	// derived secret for "derived" label with empty hash context
	emptyHash := sm3.Sum(nil)
	derivedEarly, err := HKDFExpandLabel(earlySecret, "derived", emptyHash[:], 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(derivedEarly) != 32 {
		t.Fatalf("derivedEarly length: got %d, want 32", len(derivedEarly))
	}

	// Handshake Secret = HKDF-Extract(salt=derivedEarly, IKM=shared_secret)
	// Simulate with a non-zero shared secret
	sharedSecret := bytes.Repeat([]byte{0x42}, 32)
	handshakeSecret := sm3.HKDFExtract(derivedEarly, sharedSecret)
	if len(handshakeSecret) != 32 {
		t.Fatalf("handshakeSecret length: got %d, want 32", len(handshakeSecret))
	}

	// Derive "derived" from handshake secret
	derivedHandshake, err := HKDFExpandLabel(handshakeSecret, "derived", emptyHash[:], 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(derivedHandshake) != 32 {
		t.Fatalf("derivedHandshake length: got %d, want 32", len(derivedHandshake))
	}

	// Master Secret = HKDF-Extract(salt=derivedHandshake, IKM=0^32)
	masterSecret := sm3.HKDFExtract(derivedHandshake, make([]byte, 32))
	if len(masterSecret) != 32 {
		t.Fatalf("masterSecret length: got %d, want 32", len(masterSecret))
	}

	// Verify non-trivial: master secret should not be all zeros
	if bytes.Equal(masterSecret, make([]byte, 32)) {
		t.Fatal("masterSecret is all zeros — derivation chain may be broken")
	}

	// Verify determinism: re-derive the entire chain
	earlySecret2 := sm3.HKDFExtract(nil, earlyIKM)
	if !bytes.Equal(earlySecret, earlySecret2) {
		t.Fatal("earlySecret not deterministic")
	}

	derivedEarly2, err := HKDFExpandLabel(earlySecret, "derived", emptyHash[:], 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derivedEarly, derivedEarly2) {
		t.Fatal("derivedEarly not deterministic")
	}

	handshakeSecret2 := sm3.HKDFExtract(derivedEarly, sharedSecret)
	if !bytes.Equal(handshakeSecret, handshakeSecret2) {
		t.Fatal("handshakeSecret not deterministic")
	}

	derivedHandshake2, err := HKDFExpandLabel(handshakeSecret, "derived", emptyHash[:], 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derivedHandshake, derivedHandshake2) {
		t.Fatal("derivedHandshake not deterministic")
	}

	masterSecret2 := sm3.HKDFExtract(derivedHandshake, make([]byte, 32))
	if !bytes.Equal(masterSecret, masterSecret2) {
		t.Fatal("masterSecret not deterministic")
	}
}

// TestDeriveSecretConsistency verifies DeriveSecret produces correct output
// lengths and is deterministic. It also cross-checks that DeriveSecret
// correctly hashes the transcript and passes it as context to HKDFExpandLabel.
func TestDeriveSecretConsistency(t *testing.T) {
	secret := make([]byte, 32)

	// DeriveSecret with empty transcript
	out1, err := DeriveSecret(secret, "c e traffic", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out1) != 32 {
		t.Fatalf("output length: got %d, want 32", len(out1))
	}

	// Must be deterministic
	out2, err := DeriveSecret(secret, "c e traffic", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out1, out2) {
		t.Fatal("DeriveSecret not deterministic with empty transcript")
	}

	// DeriveSecret takes the transcript HASH, not the raw transcript.
	transcript := []byte("hello tls 1.3 gm")
	transcriptHash := sm3.Sum(transcript)
	out3, err := DeriveSecret(secret, "e exp master", transcriptHash[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(out3) != 32 {
		t.Fatalf("output length: got %d, want 32", len(out3))
	}

	// Cross-verify: DeriveSecret(secret, label, hash) should equal
	// HKDFExpandLabel(secret, label, hash, 32)
	out4, err := HKDFExpandLabel(secret, "e exp master", transcriptHash[:], 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out3, out4) {
		t.Fatalf("DeriveSecret mismatch with manual HKDFExpandLabel:\n  got  %x\n  want %x", out3, out4)
	}
}

// TestDeriveSecretDifferentLabels verifies that different labels produce
// different derived secrets.
func TestDeriveSecretDifferentLabels(t *testing.T) {
	secret := make([]byte, 32)

	labels := []string{"c e traffic", "e exp master", "derived", "res master"}
	results := make(map[string]bool)

	for _, label := range labels {
		out, err := DeriveSecret(secret, label, nil)
		if err != nil {
			t.Fatal(err)
		}
		hex := hex.EncodeToString(out)
		if results[hex] {
			t.Fatalf("duplicate derived secret for label %q", label)
		}
		results[hex] = true
	}
}

// TestAEADRoundTrip verifies that AEAD encryption followed by decryption
// returns the original plaintext.
func TestAEADRoundTrip(t *testing.T) {
	key := randomSM4Key(t)
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	aead, err := NewAEAD(key, nonce)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello TLS 1.3 with SM4-GCM")
	aad := []byte("additional data")

	sealed, err := aead.Seal(0, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	opened, err := aead.Open(0, sealed, aad)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("round-trip mismatch:\n  got  %x\n  want %x", opened, plaintext)
	}
}

// TestAEADSequenceNumberIsolation verifies that different sequence numbers
// produce different ciphertexts (nonce isolation) and that a ciphertext
// sealed with one seqnum cannot be opened with a different seqnum.
func TestAEADSequenceNumberIsolation(t *testing.T) {
	key := randomSM4Key(t)
	nonce := make([]byte, 12)

	aead, err := NewAEAD(key, nonce)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("test payload")
	aad := []byte("aad")

	sealed0, err := aead.Seal(0, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	sealed1, err := aead.Seal(1, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	// Different sequence numbers must produce different ciphertexts
	if bytes.Equal(sealed0, sealed1) {
		t.Fatal("seqnum 0 and 1 produced identical ciphertext")
	}

	// Opening with wrong seqnum must fail
	_, err = aead.Open(1, sealed0, aad)
	if err == nil {
		t.Fatal("expected error when opening with wrong sequence number, got nil")
	}

	// Correct seqnum must succeed
	_, err = aead.Open(0, sealed0, aad)
	if err != nil {
		t.Fatalf("opening with correct seqnum failed: %v", err)
	}
}

// TestAEADTamperDetection verifies that AEAD detects ciphertext tampering.
func TestAEADTamperDetection(t *testing.T) {
	key := randomSM4Key(t)
	nonce := make([]byte, 12)

	aead, err := NewAEAD(key, nonce)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("sensitive data")
	aad := []byte("aad")

	sealed, err := aead.Seal(0, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the ciphertext (flip a bit in the last byte)
	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)
	tampered[len(tampered)-1] ^= 0x01

	_, err = aead.Open(0, tampered, aad)
	if err == nil {
		t.Fatal("expected error when opening tampered ciphertext, got nil")
	}

	// Also verify that tampering with AAD is detected
	tamperedAAD := []byte("bad aad")
	_, err = aead.Open(0, sealed, tamperedAAD)
	if err == nil {
		t.Fatal("expected error when opening with tampered AAD, got nil")
	}
}

// TestAEADInvalidNonce verifies that NewAEAD rejects non-12-byte nonces.
func TestAEADInvalidNonce(t *testing.T) {
	key := randomSM4Key(t)

	for _, nonceLen := range []int{0, 8, 11, 13, 16} {
		_, err := NewAEAD(key, make([]byte, nonceLen))
		if err == nil {
			t.Errorf("expected error for %d-byte nonce, got nil", nonceLen)
		}
	}
}

// TestAEADMultipleRecords verifies that multiple records can be encrypted
// and decrypted with incrementing sequence numbers.
func TestAEADMultipleRecords(t *testing.T) {
	key := randomSM4Key(t)
	nonce := make([]byte, 12)

	aead, err := NewAEAD(key, nonce)
	if err != nil {
		t.Fatal(err)
	}

	records := [][]byte{
		[]byte("record zero"),
		[]byte("record one"),
		[]byte("record two"),
		[]byte("record three"),
	}
	aad := []byte("record aad")

	var sealed [][]byte
	for i, pt := range records {
		ct, err := aead.Seal(uint64(i), pt, aad)
		if err != nil {
			t.Fatalf("Seal(%d): %v", i, err)
		}
		sealed = append(sealed, ct)
	}

	for i, ct := range sealed {
		pt, err := aead.Open(uint64(i), ct, aad)
		if err != nil {
			t.Fatalf("Open(%d): %v", i, err)
		}
		if !bytes.Equal(pt, records[i]) {
			t.Fatalf("record %d mismatch:\n  got  %x\n  want %x", i, pt, records[i])
		}
	}
}
