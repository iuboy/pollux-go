package sm2_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/iuboy/pollux-go/sm2"
)

func TestEnvelopeEncryptDecrypt(t *testing.T) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("digital envelope test payload with PKCS#7 format")

	result, err := sm2.EnvelopeEncrypt(&priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("EnvelopeEncrypt: %v", err)
	}
	if len(result.EnvelopedData) == 0 {
		t.Fatal("EnvelopedData should not be empty")
	}

	decrypted, err := sm2.EnvelopeDecrypt(priv, result)
	if err != nil {
		t.Fatalf("EnvelopeDecrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEnvelopeEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	result, err := sm2.EnvelopeEncrypt(&priv.PublicKey, []byte{})
	if err != nil {
		t.Fatalf("EnvelopeEncrypt empty: %v", err)
	}

	decrypted, err := sm2.EnvelopeDecrypt(priv, result)
	if err != nil {
		t.Fatalf("EnvelopeDecrypt empty: %v", err)
	}
	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %q", decrypted)
	}
}

func TestEnvelopeEncryptDecrypt_LargePayload(t *testing.T) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := make([]byte, 4096)
	_, _ = rand.Read(plaintext)

	result, err := sm2.EnvelopeEncrypt(&priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("EnvelopeEncrypt large: %v", err)
	}

	decrypted, err := sm2.EnvelopeDecrypt(priv, result)
	if err != nil {
		t.Fatalf("EnvelopeDecrypt large: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("large payload decrypted mismatch")
	}
}

func TestEnvelopeEncrypt_NilPublicKey(t *testing.T) {
	_, err := sm2.EnvelopeEncrypt(nil, []byte("test"))
	if err == nil {
		t.Error("should reject nil public key")
	}
}

func TestEnvelopeDecrypt_NilArgs(t *testing.T) {
	_, err := sm2.EnvelopeDecrypt(nil, &sm2.EnvelopeResult{EnvelopedData: []byte{1}})
	if err == nil {
		t.Error("should reject nil private key")
	}

	priv, _ := sm2.GenerateKey(rand.Reader)
	_, err = sm2.EnvelopeDecrypt(priv, nil)
	if err == nil {
		t.Error("should reject nil envelope")
	}
}

func TestEnvelopeSM4_EncryptDecrypt(t *testing.T) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("SM2+SM4-GCM simplified envelope test")

	encKey, nonce, ct, err := sm2.EnvelopeEncryptSM4(&priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("EnvelopeEncryptSM4: %v", err)
	}
	if len(encKey) == 0 || len(nonce) == 0 || len(ct) == 0 {
		t.Fatal("encrypted key, nonce, or ciphertext is empty")
	}

	decrypted, err := sm2.EnvelopeDecryptSM4(priv, encKey, nonce, ct)
	if err != nil {
		t.Fatalf("EnvelopeDecryptSM4: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("SM4 envelope decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEnvelopeSM4_EncryptDecrypt_EmptyPlaintext(t *testing.T) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	encKey, nonce, ct, err := sm2.EnvelopeEncryptSM4(&priv.PublicKey, []byte{})
	if err != nil {
		t.Fatalf("EnvelopeEncryptSM4 empty: %v", err)
	}

	decrypted, err := sm2.EnvelopeDecryptSM4(priv, encKey, nonce, ct)
	if err != nil {
		t.Fatalf("EnvelopeDecryptSM4 empty: %v", err)
	}
	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %q", decrypted)
	}
}

func TestEnvelopeSM4_TamperedCiphertext(t *testing.T) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("tamper detection test")
	encKey, nonce, ct, err := sm2.EnvelopeEncryptSM4(&priv.PublicKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// tamper with ciphertext
	ct[0] ^= 0xff

	_, err = sm2.EnvelopeDecryptSM4(priv, encKey, nonce, ct)
	if err == nil {
		t.Error("should reject tampered ciphertext")
	}
}

func TestEnvelopeSM4_WrongKey(t *testing.T) {
	priv1, _ := sm2.GenerateKey(rand.Reader)
	priv2, _ := sm2.GenerateKey(rand.Reader)

	plaintext := []byte("wrong key test")
	encKey, nonce, ct, _ := sm2.EnvelopeEncryptSM4(&priv1.PublicKey, plaintext)

	_, err := sm2.EnvelopeDecryptSM4(priv2, encKey, nonce, ct)
	if err == nil {
		t.Error("should reject decryption with wrong key")
	}
}

func TestEnvelopeSM4_NilPublicKey(t *testing.T) {
	_, _, _, err := sm2.EnvelopeEncryptSM4(nil, []byte("test"))
	if err == nil {
		t.Error("should reject nil public key")
	}
}

func TestEnvelopeSM4_NilPrivateKey(t *testing.T) {
	_, err := sm2.EnvelopeDecryptSM4(nil, []byte{1}, []byte{1}, []byte{1})
	if err == nil {
		t.Error("should reject nil private key")
	}
}
