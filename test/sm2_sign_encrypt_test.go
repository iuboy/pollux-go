package test

import (
	"bytes"
	"crypto/rand"
	"testing"

	polluxSM2 "github.com/ycq/pollux/sm2"
)

func TestBlackBox_SM2_SignWithSM2_WrongUID(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid := []byte("user@example.com")
	wrongUID := []byte("attacker@evil.com")
	data := []byte("SM2 sign with UID test")

	sig, err := polluxSM2.SignWithSM2(rand.Reader, priv, uid, data)
	if err != nil {
		t.Fatalf("SignWithSM2: %v", err)
	}

	if polluxSM2.VerifyWithSM2(&priv.PublicKey, wrongUID, data, sig) {
		t.Error("VerifyWithSM2 should reject wrong UID")
	}
}

func TestBlackBox_SM2_EncryptASN1_RoundTrip(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("SM2 encrypt/decrypt black-box test")

	ct, err := polluxSM2.EncryptASN1(rand.Reader, &priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("EncryptASN1: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("ciphertext should not be empty")
	}

	decrypted, err := polluxSM2.Decrypt(priv, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("roundtrip: got %q, want %q", decrypted, plaintext)
	}
}

func TestBlackBox_SM2_EncryptASN1_TamperedCiphertext(t *testing.T) {
	priv, _ := polluxSM2.GenerateKey(rand.Reader)
	ct, _ := polluxSM2.EncryptASN1(rand.Reader, &priv.PublicKey, []byte("secret"))
	ct[0] ^= 0xff
	_, err := polluxSM2.Decrypt(priv, ct)
	if err == nil {
		t.Error("should reject tampered ciphertext")
	}
}

func TestBlackBox_SM2_EncryptASN1_WrongKey(t *testing.T) {
	priv1, _ := polluxSM2.GenerateKey(rand.Reader)
	priv2, _ := polluxSM2.GenerateKey(rand.Reader)

	ct, _ := polluxSM2.EncryptASN1(rand.Reader, &priv1.PublicKey, []byte("secret"))
	_, err := polluxSM2.Decrypt(priv2, ct)
	if err == nil {
		t.Error("should reject wrong key")
	}
}

func TestBlackBox_SM2_Envelope_RoundTrip(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("SM2 envelope test data")

	env, err := polluxSM2.EnvelopeEncrypt(&priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("EnvelopeEncrypt: %v", err)
	}

	decrypted, err := polluxSM2.EnvelopeDecrypt(priv, env)
	if err != nil {
		t.Fatalf("EnvelopeDecrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("roundtrip: got %q, want %q", decrypted, plaintext)
	}
}

func TestBlackBox_SM2_EnvelopeSM4_RoundTrip(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("SM2+SM4 envelope test")

	encKey, nonce, ct, err := polluxSM2.EnvelopeEncryptSM4(&priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("EnvelopeEncryptSM4: %v", err)
	}
	if len(encKey) == 0 {
		t.Error("encrypted key should not be empty")
	}
	if len(nonce) == 0 {
		t.Error("nonce should not be empty")
	}
	if len(ct) == 0 {
		t.Error("ciphertext should not be empty")
	}

	decrypted, err := polluxSM2.EnvelopeDecryptSM4(priv, encKey, nonce, ct)
	if err != nil {
		t.Fatalf("EnvelopeDecryptSM4: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("roundtrip: got %q, want %q", decrypted, plaintext)
	}
}

func TestBlackBox_SM2_EnvelopeSM4_TamperedNonce(t *testing.T) {
	priv, _ := polluxSM2.GenerateKey(rand.Reader)
	encKey, nonce, ct, _ := polluxSM2.EnvelopeEncryptSM4(&priv.PublicKey, []byte("test"))

	nonce[0] ^= 0xff
	_, err := polluxSM2.EnvelopeDecryptSM4(priv, encKey, nonce, ct)
	if err == nil {
		t.Error("tampered nonce should cause decrypt failure")
	}
}
