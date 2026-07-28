package smx509

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	gmsmPKCS "github.com/emmansun/gmsm/pkcs"
	gmsmPKCS8 "github.com/emmansun/gmsm/pkcs8"
	"github.com/emmansun/gmsm/sm2"
	smx509 "github.com/emmansun/gmsm/smx509"
)

func TestDecryptPEMPrivateKey_Unencrypted(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	result, err := DecryptPEMPrivateKey(pemData, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result) != string(pemData) {
		t.Error("unencrypted key should be returned as-is")
	}
}

func TestDecryptPEMPrivateKey_InvalidPEM(t *testing.T) {
	_, err := DecryptPEMPrivateKey([]byte("not pem data"), "")
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestDecryptPEMPrivateKey_RSAPKCSEncrypted(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	password := []byte("test-password")
	der := x509.MarshalPKCS1PrivateKey(key)

	encBlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", der, password, x509.PEMCipherAES256) //nolint:staticcheck
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(encBlock)

	result, err := DecryptPEMPrivateKey(pemData, "test-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	block, _ := pem.Decode(result)
	if block == nil {
		t.Fatal("result is not valid PEM")
	}
	parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse decrypted key: %v", err)
	}
	if parsedKey.D.Cmp(key.D) != 0 {
		t.Error("decrypted key does not match original")
	}
}

func TestDecryptPEMPrivateKey_ECPKCSEncrypted(t *testing.T) {
	key, err := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	password := []byte("test-password")
	der, err := smx509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	encBlock, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", der, password, x509.PEMCipherAES256) //nolint:staticcheck
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(encBlock)

	result, err := DecryptPEMPrivateKey(pemData, "test-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	block, _ := pem.Decode(result)
	if block == nil {
		t.Fatal("result is not valid PEM")
	}
	// SM2 key marshaled via smx509.MarshalECPrivateKey produces SEC1 DER,
	// detectKeyType now correctly recognizes it as "EC PRIVATE KEY".
	if block.Type != "EC PRIVATE KEY" {
		t.Errorf("expected EC PRIVATE KEY, got %s", block.Type)
	}
}

func TestDecryptPEMPrivateKey_WrongPassword(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	der := x509.MarshalPKCS1PrivateKey(key)
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", der, []byte("correct"), x509.PEMCipherAES256) //nolint:staticcheck
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(encBlock)

	_, err = DecryptPEMPrivateKey(pemData, "wrong-password")
	if err == nil {
		t.Error("expected error with wrong password")
	}
}

func TestDecryptPEMPrivateKey_PKCS8Encrypted(t *testing.T) {
	// PKCS#8 加密格式应返回明确的错误提示
	pemData := []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nsomedata\n-----END ENCRYPTED PRIVATE KEY-----\n")
	_, err := DecryptPEMPrivateKey(pemData, "password")
	if err == nil {
		t.Error("expected error for PKCS#8 encrypted key")
	}
}

func TestDecryptPEMPrivateKey_PKCS8SM4CBC(t *testing.T) {
	sm2Key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	password := []byte("test-sm4-password")
	opts := &gmsmPKCS8.Opts{
		Cipher: gmsmPKCS.SM4CBC,
		KDFOpts: gmsmPKCS8.PBKDF2Opts{
			SaltSize:       16,
			IterationCount: 10000,
			HMACHash:       gmsmPKCS.SM3,
		},
	}

	encDER, err := gmsmPKCS8.MarshalPrivateKey(sm2Key, password, opts)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encDER})

	result, err := DecryptPEMPrivateKey(pemData, "test-sm4-password")
	if err != nil {
		t.Fatalf("SM4-CBC decrypt: %v", err)
	}

	block, _ := pem.Decode(result)
	if block == nil {
		t.Fatal("result is not valid PEM")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("expected PRIVATE KEY, got %s", block.Type)
	}
}

func TestDecryptPEMPrivateKey_PKCS8SM4GCM(t *testing.T) {
	sm2Key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	password := []byte("test-sm4gcm-password")
	opts := &gmsmPKCS8.Opts{
		Cipher: gmsmPKCS.SM4GCM,
		KDFOpts: gmsmPKCS8.PBKDF2Opts{
			SaltSize:       16,
			IterationCount: 10000,
			HMACHash:       gmsmPKCS.SM3,
		},
	}

	encDER, err := gmsmPKCS8.MarshalPrivateKey(sm2Key, password, opts)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encDER})

	result, err := DecryptPEMPrivateKey(pemData, "test-sm4gcm-password")
	if err != nil {
		t.Fatalf("SM4-GCM decrypt: %v", err)
	}

	block, _ := pem.Decode(result)
	if block == nil {
		t.Fatal("result is not valid PEM")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("expected PRIVATE KEY, got %s", block.Type)
	}
}

func TestDecryptPEMPrivateKey_PKCS8SM4WrongPassword(t *testing.T) {
	sm2Key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	password := []byte("correct-password")
	opts := &gmsmPKCS8.Opts{
		Cipher: gmsmPKCS.SM4CBC,
		KDFOpts: gmsmPKCS8.PBKDF2Opts{
			SaltSize:       16,
			IterationCount: 10000,
			HMACHash:       gmsmPKCS.SM3,
		},
	}

	encDER, err := gmsmPKCS8.MarshalPrivateKey(sm2Key, password, opts)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encDER})

	_, err = DecryptPEMPrivateKey(pemData, "wrong-password")
	if err == nil {
		t.Error("expected error with wrong password")
	}
}

// TestDecryptPEMPrivateKey_PKCS8RejectsSHA1PRF verifies that a PKCS#8 encrypted
// key using HMAC-SHA1 as the PBKDF2 PRF is REJECTED. SHA1 is cryptographically
// broken; before the fix in decryptPKCS8/newPRF, an unknown/SHA1 PRF silently
// fell back to sha1.New, weakening offline brute-force resistance of
// attacker-supplied encrypted keys.
//
// Regression guard for the newPRF fail-closed change.
func TestDecryptPEMPrivateKey_PKCS8RejectsSHA1PRF(t *testing.T) {
	sm2Key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	password := []byte("sha1-prf-password")
	// gmsm still supports emitting HMAC-SHA1 PBKDF2 params; we use it to craft
	// a key that pollux must refuse to decrypt.
	opts := &gmsmPKCS8.Opts{
		Cipher: gmsmPKCS.SM4CBC,
		KDFOpts: gmsmPKCS8.PBKDF2Opts{
			SaltSize:       16,
			IterationCount: 10000,
			HMACHash:       gmsmPKCS.SHA1,
		},
	}

	encDER, err := gmsmPKCS8.MarshalPrivateKey(sm2Key, password, opts)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encDER})

	_, err = DecryptPEMPrivateKey(pemData, "sha1-prf-password")
	if err == nil {
		t.Fatal("expected HMAC-SHA1 PRF to be rejected, but decryption succeeded")
	}
	// Error message must point at the PRF (not a generic decrypt/padding failure),
	// so a misconfigured key produces a diagnosable error rather than a confusing
	// "decryption failed" that suggests a wrong password.
	if !strings.Contains(err.Error(), "PRF") {
		t.Errorf("expected error to mention PRF, got: %v", err)
	}
}
