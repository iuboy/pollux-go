package test

import (
	"bytes"
	"crypto/rand"
	"testing"

	polluxSM2 "github.com/iuboy/pollux-go/sm2"
)

// ========== 密钥序列化 ==========

func TestBlackBox_SM2_ByteRoundTrip(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// PrivateKeyToBytes（已移除）的替代是 PrivateKeyToBytesSecure，Destroy 清零敏感内存。
	skb, err := polluxSM2.PrivateKeyToBytesSecure(priv)
	if err != nil {
		t.Fatalf("PrivateKeyToBytesSecure: %v", err)
	}
	defer skb.Destroy()
	privBytes := skb.Data()
	if len(privBytes) == 0 {
		t.Fatal("PrivateKeyToBytesSecure returned empty")
	}

	parsed, err := polluxSM2.BytesToPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("BytesToPrivateKey: %v", err)
	}
	if parsed.D.Cmp(priv.D) != 0 {
		t.Error("private key roundtrip mismatch")
	}

	// PublicKeyToBytes（已移除）的替代是 MarshalUncompressed。
	pubBytes := polluxSM2.MarshalUncompressed(&priv.PublicKey)
	if len(pubBytes) == 0 {
		t.Fatal("MarshalUncompressed returned empty")
	}

	// BytesToPublicKey（已移除）的替代是 UnmarshalUncompressed。
	parsedPub, err := polluxSM2.UnmarshalUncompressed(pubBytes)
	if err != nil {
		t.Fatalf("UnmarshalUncompressed: %v", err)
	}
	if !parsedPub.Equal(&priv.PublicKey) {
		t.Error("public key roundtrip mismatch")
	}
}

func TestBlackBox_SM2_MarshalUncompressed(t *testing.T) {
	priv, _ := polluxSM2.GenerateKey(rand.Reader)

	pubBytes := polluxSM2.MarshalUncompressed(&priv.PublicKey)
	if len(pubBytes) == 0 {
		t.Fatal("MarshalUncompressed returned empty")
	}

	pub, err := polluxSM2.UnmarshalUncompressed(pubBytes)
	if err != nil {
		t.Fatalf("UnmarshalUncompressed: %v", err)
	}
	if !pub.Equal(&priv.PublicKey) {
		t.Error("uncompressed roundtrip mismatch")
	}
}

func TestBlackBox_SM2_NewPrivateKey(t *testing.T) {
	priv, _ := polluxSM2.GenerateKey(rand.Reader)
	// PrivateKeyToBytes（已移除）的替代是 PrivateKeyToBytesSecure，Destroy 清零敏感内存。
	skb, err := polluxSM2.PrivateKeyToBytesSecure(priv)
	if err != nil {
		t.Fatalf("PrivateKeyToBytesSecure: %v", err)
	}
	defer skb.Destroy()
	raw := skb.Data()

	parsed, err := polluxSM2.NewPrivateKey(raw)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	if parsed.D.Cmp(priv.D) != 0 {
		t.Error("NewPrivateKey mismatch")
	}
}

func TestBlackBox_SM2_NewPrivateKey_Invalid(t *testing.T) {
	_, err := polluxSM2.NewPrivateKey([]byte{0x00, 0x01})
	if err == nil {
		t.Error("should reject invalid key bytes")
	}
}

func TestBlackBox_SM2_NewPublicKey(t *testing.T) {
	priv, _ := polluxSM2.GenerateKey(rand.Reader)
	// PublicKeyToBytes（已移除）的替代是 MarshalUncompressed。
	pubDER := polluxSM2.MarshalUncompressed(&priv.PublicKey)

	parsed, err := polluxSM2.NewPublicKey(pubDER)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	if !parsed.Equal(&priv.PublicKey) {
		t.Error("NewPublicKey mismatch")
	}
}

func TestBlackBox_SM2_NewPublicKey_Invalid(t *testing.T) {
	_, err := polluxSM2.NewPublicKey([]byte{0x00})
	if err == nil {
		t.Error("should reject invalid key bytes")
	}
}

func TestBlackBox_SM2_PublicKeyPEM(t *testing.T) {
	priv, _ := polluxSM2.GenerateKey(rand.Reader)

	pemData, err := polluxSM2.WritePublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("WritePublicKeyToPEM: %v", err)
	}

	parsed, err := polluxSM2.ParsePublicKeyFromPEM(pemData)
	if err != nil {
		t.Fatalf("ParsePublicKeyFromPEM: %v", err)
	}
	if !parsed.Equal(&priv.PublicKey) {
		t.Error("public key PEM roundtrip mismatch")
	}
}

func TestBlackBox_SM2_PrivateKeyPEM(t *testing.T) {
	priv, _ := polluxSM2.GenerateKey(rand.Reader)

	pemData, err := polluxSM2.WritePrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("WritePrivateKeyToPEM: %v", err)
	}

	parsed, err := polluxSM2.ParsePrivateKeyFromPEM(pemData)
	if err != nil {
		t.Fatalf("ParsePrivateKeyFromPEM: %v", err)
	}
	if parsed.D.Cmp(priv.D) != 0 {
		t.Error("private key PEM roundtrip mismatch")
	}
}

func TestBlackBox_SM2_GenerateKeyDefault(t *testing.T) {
	key, err := polluxSM2.GenerateKeyDefault()
	if err != nil {
		t.Fatalf("GenerateKeyDefault: %v", err)
	}
	if key == nil {
		t.Fatal("key should not be nil")
	}
}

func TestBlackBox_SM2_NewSM2SignerOption(t *testing.T) {
	uid := []byte("1234567812345678")
	opts := polluxSM2.NewSM2SignerOption(true, uid)
	if opts == nil {
		t.Fatal("NewSM2SignerOption returned nil")
	}

	key, _ := polluxSM2.GenerateKey(rand.Reader)
	digest := []byte("test with NewSM2SignerOption")

	sig, err := polluxSM2.SignASN1(rand.Reader, key, digest, opts)
	if err != nil {
		t.Fatalf("SignASN1 with NewSM2SignerOption: %v", err)
	}
	if !polluxSM2.VerifyWithSM2(&key.PublicKey, uid, digest, sig) {
		t.Error("VerifyWithSM2 failed for NewSM2SignerOption signature")
	}
}

// ========== 密钥交换 ==========

func TestBlackBox_SM2_KeyExchange(t *testing.T) {
	alicePriv, _ := polluxSM2.GenerateKey(rand.Reader)
	bobPriv, _ := polluxSM2.GenerateKey(rand.Reader)

	alice, err := polluxSM2.NewKeyExchangePerformer(alicePriv, &bobPriv.PublicKey, []byte("alice@test.com"), []byte("bob@test.com"), 32)
	if err != nil {
		t.Fatalf("NewKeyExchangePerformer alice: %v", err)
	}
	bob, err := polluxSM2.NewKeyExchangePerformer(bobPriv, &alicePriv.PublicKey, []byte("bob@test.com"), []byte("alice@test.com"), 32)
	if err != nil {
		t.Fatalf("NewKeyExchangePerformer bob: %v", err)
	}

	aliceEph, _ := alice.GenerateEphemeralKey()
	bobEph, _ := bob.GenerateEphemeralKey()

	bobShared, bobSig, err := bob.ComputeSharedSecretAsResponder(rand.Reader, aliceEph)
	if err != nil {
		t.Fatalf("Bob ComputeSharedSecretAsResponder: %v", err)
	}

	aliceShared, _, err := alice.ComputeSharedSecretAsInitiator(bobEph, bobSig)
	if err != nil {
		t.Fatalf("Alice ComputeSharedSecretAsInitiator: %v", err)
	}

	if !bytes.Equal(aliceShared, bobShared) {
		t.Errorf("shared key mismatch:\n  alice=%x\n  bob  =%x", aliceShared, bobShared)
	}
}

func TestBlackBox_SM2_KeyExchange_DifferentKeyLengths(t *testing.T) {
	priv1, _ := polluxSM2.GenerateKey(rand.Reader)
	priv2, _ := polluxSM2.GenerateKey(rand.Reader)

	for _, klen := range []int{16, 24, 32} {
		t.Run("", func(t *testing.T) {
			p1, err := polluxSM2.NewKeyExchangePerformer(priv1, &priv2.PublicKey, []byte("A"), []byte("B"), klen)
			if err != nil {
				t.Fatal(err)
			}
			p2, err := polluxSM2.NewKeyExchangePerformer(priv2, &priv1.PublicKey, []byte("B"), []byte("A"), klen)
			if err != nil {
				t.Fatal(err)
			}

			eph1, _ := p1.GenerateEphemeralKey()
			eph2, _ := p2.GenerateEphemeralKey()

			shared2, sig2, _ := p2.ComputeSharedSecretAsResponder(rand.Reader, eph1)
			shared1, _, _ := p1.ComputeSharedSecretAsInitiator(eph2, sig2)

			if len(shared1) != klen {
				t.Errorf("key length: got %d, want %d", len(shared1), klen)
			}
			if !bytes.Equal(shared1, shared2) {
				t.Error("shared keys mismatch")
			}
		})
	}
}

// ========== 数字信封 SM4 ==========

func TestBlackBox_SM2_EnvelopeSM4(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("SM2+SM4-GCM black-box envelope test")
	encKey, nonce, ct, err := polluxSM2.EnvelopeEncryptSM4(&priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("EnvelopeEncryptSM4: %v", err)
	}
	if len(encKey) == 0 || len(nonce) == 0 || len(ct) == 0 {
		t.Fatal("encrypted key, nonce, or ciphertext is empty")
	}

	decrypted, err := polluxSM2.EnvelopeDecryptSM4(priv, encKey, nonce, ct)
	if err != nil {
		t.Fatalf("EnvelopeDecryptSM4: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("roundtrip: got %q, want %q", decrypted, plaintext)
	}
}

func TestBlackBox_SM2_EnvelopeSM4_Empty(t *testing.T) {
	priv, _ := polluxSM2.GenerateKey(rand.Reader)
	encKey, nonce, ct, _ := polluxSM2.EnvelopeEncryptSM4(&priv.PublicKey, []byte{})
	decrypted, _ := polluxSM2.EnvelopeDecryptSM4(priv, encKey, nonce, ct)
	if len(decrypted) != 0 {
		t.Errorf("expected empty, got %q", decrypted)
	}
}

func TestBlackBox_SM2_EnvelopeSM4_LargePayload(t *testing.T) {
	priv, _ := polluxSM2.GenerateKey(rand.Reader)
	plaintext := make([]byte, 8192)
	_, _ = rand.Read(plaintext)

	encKey, nonce, ct, _ := polluxSM2.EnvelopeEncryptSM4(&priv.PublicKey, plaintext)
	decrypted, err := polluxSM2.EnvelopeDecryptSM4(priv, encKey, nonce, ct)
	if err != nil {
		t.Fatalf("EnvelopeDecryptSM4 large: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("large payload roundtrip mismatch")
	}
}

func TestBlackBox_SM2_EnvelopeSM4_Tampered(t *testing.T) {
	priv, _ := polluxSM2.GenerateKey(rand.Reader)
	encKey, nonce, ct, _ := polluxSM2.EnvelopeEncryptSM4(&priv.PublicKey, []byte("tamper test"))
	ct[0] ^= 0xff
	_, err := polluxSM2.EnvelopeDecryptSM4(priv, encKey, nonce, ct)
	if err == nil {
		t.Error("should reject tampered ciphertext")
	}
}

func TestBlackBox_SM2_EnvelopeSM4_WrongKey(t *testing.T) {
	priv1, _ := polluxSM2.GenerateKey(rand.Reader)
	priv2, _ := polluxSM2.GenerateKey(rand.Reader)
	encKey, nonce, ct, _ := polluxSM2.EnvelopeEncryptSM4(&priv1.PublicKey, []byte("wrong key"))
	_, err := polluxSM2.EnvelopeDecryptSM4(priv2, encKey, nonce, ct)
	if err == nil {
		t.Error("should reject wrong key")
	}
}

func TestBlackBox_SM2_EnvelopeSM4_NilArgs(t *testing.T) {
	_, _, _, err := polluxSM2.EnvelopeEncryptSM4(nil, []byte("test"))
	if err == nil {
		t.Error("should reject nil public key")
	}
}

// ========== P256 / Compress ==========

func TestBlackBox_SM2_P256(t *testing.T) {
	curve := polluxSM2.P256()
	if curve == nil {
		t.Fatal("P256() returned nil")
	}
	if curve.Params().BitSize != 256 {
		t.Errorf("P256 bit size: got %d, want 256", curve.Params().BitSize)
	}
}

func TestBlackBox_SM2_CompressDecompress(t *testing.T) {
	priv, _ := polluxSM2.GenerateKey(rand.Reader)
	compressed := polluxSM2.CompressPublicKey(&priv.PublicKey)
	if len(compressed) != 33 {
		t.Errorf("compressed length: got %d, want 33", len(compressed))
	}
	pub, err := polluxSM2.DecompressPublicKey(compressed)
	if err != nil {
		t.Fatalf("DecompressPublicKey: %v", err)
	}
	if !pub.Equal(&priv.PublicKey) {
		t.Error("decompressed key mismatch")
	}
}

func TestBlackBox_SM2_Decompress_Invalid(t *testing.T) {
	_, err := polluxSM2.DecompressPublicKey([]byte{0x00})
	if err == nil {
		t.Error("should reject invalid compressed key")
	}
}
