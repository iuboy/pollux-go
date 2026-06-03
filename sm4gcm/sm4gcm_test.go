package sm4gcm

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	k1, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != KeySize {
		t.Fatalf("key size: got %d, want %d", len(k1), KeySize)
	}
	k2, _ := GenerateKey(rand.Reader)
	if bytes.Equal(k1, k2) {
		t.Error("two keys should differ")
	}
}

func TestGenerateNonce(t *testing.T) {
	n, err := GenerateNonce(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(n) != NonceSize {
		t.Fatalf("nonce size: got %d, want %d", len(n), NonceSize)
	}
}

func TestSealOpen_RoundTrip(t *testing.T) {
	key, _ := GenerateKey(rand.Reader)
	nonce, _ := GenerateNonce(rand.Reader)
	pt := []byte("hello sm4gcm")
	aad := []byte("additional data")

	ct, err := Seal(key, nonce, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, nonce, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Error("roundtrip mismatch")
	}
}

func TestSealOpen_NoAAD(t *testing.T) {
	key, _ := GenerateKey(rand.Reader)
	nonce, _ := GenerateNonce(rand.Reader)
	pt := []byte("no aad")

	ct, _ := Seal(key, nonce, pt, nil)
	got, err := Open(key, nonce, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Error("roundtrip mismatch")
	}
}

func TestOpen_WrongKey(t *testing.T) {
	key1, _ := GenerateKey(rand.Reader)
	key2, _ := GenerateKey(rand.Reader)
	nonce, _ := GenerateNonce(rand.Reader)

	ct, _ := Seal(key1, nonce, []byte("secret"), nil)
	_, err := Open(key2, nonce, ct, nil)
	if err == nil {
		t.Error("wrong key should fail")
	}
}

func TestOpen_AADTamper(t *testing.T) {
	key, _ := GenerateKey(rand.Reader)
	nonce, _ := GenerateNonce(rand.Reader)

	ct, _ := Seal(key, nonce, []byte("data"), []byte("aad1"))
	_, err := Open(key, nonce, ct, []byte("aad2"))
	if err == nil {
		t.Error("AAD tamper should fail")
	}
}

func TestOpen_TagTamper(t *testing.T) {
	key, _ := GenerateKey(rand.Reader)
	nonce, _ := GenerateNonce(rand.Reader)

	ct, _ := Seal(key, nonce, []byte("data"), nil)
	ct[0] ^= 0xff
	_, err := Open(key, nonce, ct, nil)
	if err == nil {
		t.Error("tag tamper should fail")
	}
}

func TestSeal_InvalidNonceSize(t *testing.T) {
	key, _ := GenerateKey(rand.Reader)
	_, err := Seal(key, make([]byte, 16), []byte("x"), nil)
	if err == nil {
		t.Error("invalid nonce size should fail")
	}
}

func TestSeal_InvalidKeySize(t *testing.T) {
	_, err := Seal(make([]byte, 15), make([]byte, NonceSize), []byte("x"), nil)
	if err == nil {
		t.Error("invalid key size should fail")
	}
}

func TestSealRandomNonce(t *testing.T) {
	key, _ := GenerateKey(rand.Reader)
	pt := []byte("seal with random nonce")

	s1, err := SealRandomNonce(rand.Reader, key, pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s1.Nonce) != NonceSize {
		t.Fatalf("nonce size: got %d", len(s1.Nonce))
	}

	got, err := Open(key, s1.Nonce, s1.Ciphertext, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Error("roundtrip mismatch")
	}

	s2, _ := SealRandomNonce(rand.Reader, key, pt, nil)
	if bytes.Equal(s1.Nonce, s2.Nonce) {
		t.Error("two nonces should differ")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("fail") }

func TestGenerateKey_FailingReader(t *testing.T) {
	_, err := GenerateKey(failingReader{})
	if err == nil {
		t.Error("failing reader should return error")
	}
}

func TestGenerateNonce_FailingReader(t *testing.T) {
	_, err := GenerateNonce(failingReader{})
	if err == nil {
		t.Error("failing reader should return error")
	}
}
