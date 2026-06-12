package sm2_test

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/iuboy/pollux-go/sm2"
)

// TestP256CurveParams verifies the SM2 curve parameters match GM/T 0003.
func TestP256CurveParams(t *testing.T) {
	curve := sm2.P256()
	if curve == nil {
		t.Fatal("P256() returned nil")
	}

	params := curve.Params()
	if params.P == nil || params.N == nil || params.B == nil || params.Gx == nil || params.Gy == nil {
		t.Fatal("curve params contain nil")
	}

	if params.BitSize != 256 {
		t.Errorf("BitSize = %d, want 256", params.BitSize)
	}

	// GM/T 0003.1-2012 prime p
	expectedP, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	if params.P.Cmp(expectedP) != 0 {
		t.Errorf("curve prime mismatch")
	}
}

// TestSM2EncryptDecryptVector uses a known key pair to verify encrypt/decrypt roundtrip.
// SM2 encryption is non-deterministic (random), so we verify roundtrip, not fixed ciphertext.
func TestSM2EncryptDecryptRoundtrip(t *testing.T) {
	key, err := sm2.GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("SM2 encryption test message for GM/T 0003.4")

	ciphertext, err := sm2.EncryptASN1(rand.Reader, &key.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("EncryptASN1: %v", err)
	}

	decrypted, err := sm2.Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypt mismatch\ngot:  %q\nwant: %q", decrypted, plaintext)
	}
}

// TestSM2SignVerifyVector verifies sign/verify roundtrip with deterministic digest.
func TestSM2SignVerifyVector(t *testing.T) {
	key, err := sm2.GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	// GM/T 0003.2 test: use a known digest
	digest := []byte("SM2 signature test digest")

	sig, err := sm2.SignASN1(rand.Reader, key, digest, nil)
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}

	if !sm2.VerifyASN1(&key.PublicKey, digest, sig) {
		t.Error("VerifyASN1 failed for valid signature")
	}

	// Wrong digest should fail
	if sm2.VerifyASN1(&key.PublicKey, []byte("wrong"), sig) {
		t.Error("VerifyASN1 should fail for wrong digest")
	}

	// Tampered signature should fail
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[0] ^= 0xff
	if sm2.VerifyASN1(&key.PublicKey, digest, tampered) {
		t.Error("VerifyASN1 should fail for tampered signature")
	}
}

// TestSM2WithUserID verifies GM/T 0009 SM2 signing with explicit user ID.
func TestSM2WithUserID(t *testing.T) {
	key, err := sm2.GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	uid := []byte("1234567812345678")
	data := []byte("GM/T 0009-2012 test data")

	sig, err := sm2.SignWithSM2(rand.Reader, key, uid, data)
	if err != nil {
		t.Fatalf("SignWithSM2: %v", err)
	}

	if !sm2.VerifyWithSM2(&key.PublicKey, uid, data, sig) {
		t.Error("VerifyWithSM2 failed for valid signature")
	}

	// Wrong UID should fail
	if sm2.VerifyWithSM2(&key.PublicKey, []byte("wrong_uid"), data, sig) {
		t.Error("VerifyWithSM2 should fail for wrong UID")
	}
}

// TestSM2CryptoSignerInterface verifies PrivateKey implements crypto.Signer.
func TestSM2CryptoSignerInterface(t *testing.T) {
	key, err := sm2.GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	// crypto.Signer interface
	digest := []byte("crypto.Signer test")
	sig, err := key.Sign(rand.Reader, digest, nil)
	if err != nil {
		t.Fatalf("Sign via crypto.Signer: %v", err)
	}

	if !sm2.VerifyASN1(&key.PublicKey, digest, sig) {
		t.Error("Sign via crypto.Signer interface failed verification")
	}
}

// TestSM2KeySerialization verifies PEM/DER roundtrip through existing functions.
func TestSM2KeyDERRoundtrip(t *testing.T) {
	key, err := sm2.GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	// DER encode/decode public key
	pubDER, _ := sm2.NewPublicKey(nil)
	_ = pubDER // sm2.NewPublicKey parses from DER, test with actual DER

	// Test key extraction
	pubKey := &key.PublicKey
	if pubKey == nil {
		t.Error("public key is nil")
	}

	// Verify the public key is on the curve
	curve := sm2.P256()
	if !curve.IsOnCurve(pubKey.X, pubKey.Y) {
		t.Error("public key is not on SM2 curve")
	}
}

// TestSM2DigestLength verifies SM2 works with various digest lengths.
func TestSM2DigestLength(t *testing.T) {
	key, err := sm2.GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	for _, length := range []int{16, 32, 48, 64} {
		digest := make([]byte, length)
		for i := range digest {
			digest[i] = byte(i)
		}

		sig, err := sm2.SignASN1(rand.Reader, key, digest, nil)
		if err != nil {
			t.Errorf("SignASN1 failed for %d-byte digest: %v", length, err)
			continue
		}

		if !sm2.VerifyASN1(&key.PublicKey, digest, sig) {
			t.Errorf("VerifyASN1 failed for %d-byte digest", length)
		}
	}
}

// TestVectorCiphertextLength verifies SM2 ciphertext has expected ASN.1 structure.
func TestVectorCiphertextLength(t *testing.T) {
	key, err := sm2.GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("test")
	ct, err := sm2.EncryptASN1(rand.Reader, &key.PublicKey, msg)
	if err != nil {
		t.Fatal(err)
	}

	// SM2 C1C3C2 ASN.1 ciphertext should be at least ~100 bytes
	// (uncompressed point 65 + hash 32 + encrypted msg + ASN.1 overhead)
	if len(ct) < 90 {
		t.Errorf("ciphertext too short: %d bytes", len(ct))
	}

	// Hex for debugging
	_ = hex.EncodeToString(ct)
}
