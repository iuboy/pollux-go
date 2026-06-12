package test

import (
	"bytes"
	"crypto/rand"
	"testing"

	polluxSM4GCM "github.com/iuboy/pollux-go/sm4gcm"
)

func TestBlackBox_SM4GCM_GenerateKey_Size(t *testing.T) {
	key, err := polluxSM4GCM.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(key) != polluxSM4GCM.KeySize {
		t.Errorf("key length: got %d, want %d", len(key), polluxSM4GCM.KeySize)
	}
}

func TestBlackBox_SM4GCM_GenerateKey_Unique(t *testing.T) {
	k1, _ := polluxSM4GCM.GenerateKey(rand.Reader)
	k2, _ := polluxSM4GCM.GenerateKey(rand.Reader)
	if bytes.Equal(k1, k2) {
		t.Error("two generated keys should differ")
	}
}

func TestBlackBox_SM4GCM_GenerateNonce_Size(t *testing.T) {
	nonce, err := polluxSM4GCM.GenerateNonce(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	if len(nonce) != polluxSM4GCM.NonceSize {
		t.Errorf("nonce length: got %d, want %d", len(nonce), polluxSM4GCM.NonceSize)
	}
}

func TestBlackBox_SM4GCM_SealOpen_RoundTrip(t *testing.T) {
	key, _ := polluxSM4GCM.GenerateKey(rand.Reader)
	nonce, _ := polluxSM4GCM.GenerateNonce(rand.Reader)
	plaintext := []byte("SM4-GCM black-box round trip test")
	aad := []byte("additional-data")

	ct, err := polluxSM4GCM.Seal(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	pt, err := polluxSM4GCM.Open(key, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("roundtrip: got %q, want %q", pt, plaintext)
	}
}

func TestBlackBox_SM4GCM_Open_WrongKey(t *testing.T) {
	key, _ := polluxSM4GCM.GenerateKey(rand.Reader)
	wrongKey, _ := polluxSM4GCM.GenerateKey(rand.Reader)
	nonce, _ := polluxSM4GCM.GenerateNonce(rand.Reader)

	ct, _ := polluxSM4GCM.Seal(key, nonce, []byte("secret"), nil)
	_, err := polluxSM4GCM.Open(wrongKey, nonce, ct, nil)
	if err == nil {
		t.Error("Open with wrong key should fail")
	}
}

func TestBlackBox_SM4GCM_Open_AADTamperRejected(t *testing.T) {
	key, _ := polluxSM4GCM.GenerateKey(rand.Reader)
	nonce, _ := polluxSM4GCM.GenerateNonce(rand.Reader)

	ct, _ := polluxSM4GCM.Seal(key, nonce, []byte("data"), []byte("aad-original"))
	_, err := polluxSM4GCM.Open(key, nonce, ct, []byte("aad-tampered"))
	if err == nil {
		t.Error("Open with tampered AAD should fail")
	}
}

func TestBlackBox_SM4GCM_Open_TagTamperRejected(t *testing.T) {
	key, _ := polluxSM4GCM.GenerateKey(rand.Reader)
	nonce, _ := polluxSM4GCM.GenerateNonce(rand.Reader)

	ct, _ := polluxSM4GCM.Seal(key, nonce, []byte("data"), nil)
	ct[len(ct)-1] ^= 0xff
	_, err := polluxSM4GCM.Open(key, nonce, ct, nil)
	if err == nil {
		t.Error("Open with tampered tag should fail")
	}
}

func TestBlackBox_SM4GCM_Seal_InvalidKeySize(t *testing.T) {
	nonce, _ := polluxSM4GCM.GenerateNonce(rand.Reader)
	_, err := polluxSM4GCM.Seal([]byte("short"), nonce, []byte("data"), nil)
	if err == nil {
		t.Error("Seal with wrong key size should fail")
	}
}

func TestBlackBox_SM4GCM_Seal_InvalidNonceSize(t *testing.T) {
	key, _ := polluxSM4GCM.GenerateKey(rand.Reader)
	_, err := polluxSM4GCM.Seal(key, []byte("short"), []byte("data"), nil)
	if err == nil {
		t.Error("Seal with wrong nonce size should fail")
	}
}

func TestBlackBox_SM4GCM_SealRandomNonce_ReturnsNonce(t *testing.T) {
	key, _ := polluxSM4GCM.GenerateKey(rand.Reader)
	plaintext := []byte("auto-nonce test")
	aad := []byte("aad")

	sealed, err := polluxSM4GCM.SealRandomNonce(rand.Reader, key, plaintext, aad)
	if err != nil {
		t.Fatalf("SealRandomNonce: %v", err)
	}
	if len(sealed.Nonce) != polluxSM4GCM.NonceSize {
		t.Errorf("nonce length: got %d, want %d", len(sealed.Nonce), polluxSM4GCM.NonceSize)
	}
	if len(sealed.Ciphertext) == 0 {
		t.Error("ciphertext should not be empty")
	}

	pt, err := polluxSM4GCM.Open(key, sealed.Nonce, sealed.Ciphertext, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("roundtrip: got %q, want %q", pt, plaintext)
	}
}
