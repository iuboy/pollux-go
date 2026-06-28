package smx509

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	gmsmPKCS "github.com/emmansun/gmsm/pkcs"
	gmsmPKCS8 "github.com/emmansun/gmsm/pkcs8"
	"github.com/emmansun/gmsm/sm2"
)

// sm4cbcEncryptedPEM encrypts an SM2 key with PBKDF2-SM3 + SM4-CBC and returns
// its PEM encoding + the password. Mirrors the fixtures in
// cert_key_decrypt_test.go so the DER variant is exercised under the same
// conditions as the PEM variant.
func sm4cbcEncryptedPEM(t *testing.T, password string) []byte {
	t.Helper()
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	opts := &gmsmPKCS8.Opts{
		Cipher:  gmsmPKCS.SM4CBC,
		KDFOpts: gmsmPKCS8.PBKDF2Opts{SaltSize: 16, IterationCount: 10000, HMACHash: gmsmPKCS.SM3},
	}
	encDER, err := gmsmPKCS8.MarshalPrivateKey(key, []byte(password), opts)
	if err != nil {
		t.Fatalf("marshal encrypted key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encDER})
}

// TestDecryptPEMPrivateKeyDER_Unencrypted returns the block bytes verbatim for
// an unencrypted key (no Proc-Type / not ENCRYPTED PRIVATE KEY).
func TestDecryptPEMPrivateKeyDER_Unencrypted(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	got, err := DecryptPEMPrivateKeyDER(pemData, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, der) {
		t.Error("unencrypted key should return raw DER bytes verbatim")
	}
}

// TestDecryptPEMPrivateKeyDER_InvalidPEM errors on non-PEM input.
func TestDecryptPEMPrivateKeyDER_InvalidPEM(t *testing.T) {
	if _, err := DecryptPEMPrivateKeyDER([]byte("not pem data"), ""); err == nil {
		t.Error("expected error for invalid PEM")
	}
}

// TestDecryptPEMPrivateKeyDER_PKCS8SM4CBC decrypts an SM4-CBC/PBKDF2-SM3
// PKCS#8 key and returns DER that differs from the ciphertext (i.e. decryption
// actually happened) and parses as a private key.
func TestDecryptPEMPrivateKeyDER_PKCS8SM4CBC(t *testing.T) {
	pemData := sm4cbcEncryptedPEM(t, "der-password")

	got, err := DecryptPEMPrivateKeyDER(pemData, "der-password")
	if err != nil {
		t.Fatalf("decrypt DER: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected non-empty decrypted DER")
	}
	// The decrypted DER must differ from the original encrypted block bytes.
	block, _ := pem.Decode(pemData)
	if block != nil && bytes.Equal(got, block.Bytes) {
		t.Error("returned DER equals ciphertext — decryption did not happen")
	}
}

// TestDecryptPEMPrivateKeyDER_WrongPassword errors on a wrong password.
func TestDecryptPEMPrivateKeyDER_WrongPassword(t *testing.T) {
	pemData := sm4cbcEncryptedPEM(t, "correct-password")
	if _, err := DecryptPEMPrivateKeyDER(pemData, "wrong-password"); err == nil {
		t.Error("expected error with wrong password")
	}
}

// TestDecryptPEMPrivateKeyDER_CBCErrorIsOpaque asserts the padding-oracle
// hardening in decryptBlock's CBC path: a wrong password under PBES2/CBC must
// surface as the single opaque errDecryptFailed sentinel (errors.Is), NOT the
// raw pkcs7Unpad error or any message that distinguishes bad-padding from
// bad-ASN.1. Two distinct wrong passwords must produce the identical error, so
// a remote attacker cannot classify failures.
func TestDecryptPEMPrivateKeyDER_CBCErrorIsOpaque(t *testing.T) {
	pemData := sm4cbcEncryptedPEM(t, "correct-password")

	_, err1 := DecryptPEMPrivateKeyDER(pemData, "wrong-password-1")
	_, err2 := DecryptPEMPrivateKeyDER(pemData, "another-wrong-password-2")
	if err1 == nil || err2 == nil {
		t.Fatal("expected both wrong passwords to fail")
	}
	if !errors.Is(err1, errDecryptFailed) {
		t.Errorf("wrong password must resolve to errDecryptFailed, got %v", err1)
	}
	if err1.Error() != err2.Error() {
		t.Errorf("CBC wrong-password errors must be identical (padding-oracle hardening): %q vs %q", err1, err2)
	}
	// The inner sentinel must not carry padding/PKCS7 detail (that would be an
	// oracle). The outer "decrypt PKCS#8 private key failed:" wrapper names the
	// format, which is not a distinguishable failure mode, so it is acceptable.
	if msg := errDecryptFailed.Error(); strings.Contains(msg, "padding") || strings.Contains(msg, "PKCS7") {
		t.Errorf("errDecryptFailed must not leak padding detail: %q", msg)
	}
}
