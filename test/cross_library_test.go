//go:build integration

package test

import (
	"os/exec"
	"testing"

	polluxSm2 "github.com/iuboy/pollux-go/sm2"
	polluxSmx509 "github.com/iuboy/pollux-go/smx509"
)

const tongsuoBin = "/opt/local/tongsuo/bin/openssl"

func tongsuoAvailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath(tongsuoBin); err != nil {
		t.Skip("Tongsuo not available")
	}
}

// TestCertInteropParse verifies Tongsuo-generated SM2 certificates are
// parseable by pollux/smx509 with correct field extraction.
func TestCertInteropParse(t *testing.T) {
	tongsuoAvailable(t)

	certPEM := readCert(t, "sm2_sign_cert.pem")

	smCert, err := polluxSmx509.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	if smCert.Subject.CommonName != "localhost-sign" {
		t.Errorf("CommonName: got %q, want %q", smCert.Subject.CommonName, "localhost-sign")
	}
	if smCert.SerialNumber == nil {
		t.Error("SerialNumber is nil")
	}
}

// TestSM2KeyInterop verifies SM2 keys round-trip between Tongsuo and pollux/sm2.
func TestSM2KeyInterop(t *testing.T) {
	tongsuoAvailable(t)

	// Parse Tongsuo-generated key with pollux/sm2
	keyPEM := readCert(t, "sm2_sign_key.pem")
	key, err := polluxSm2.ParsePrivateKeyFromPEM(keyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyFromPEM: %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}

	// Write it back and re-parse
	written, err := polluxSm2.WritePrivateKeyToPEM(key)
	if err != nil {
		t.Fatalf("WritePrivateKeyToPEM: %v", err)
	}

	key2, err := polluxSm2.ParsePrivateKeyFromPEM(written)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if key2 == nil {
		t.Fatal("re-parsed key is nil")
	}
}

// TestDecryptTongsuoEncryptedKey verifies pollux/smx509 can decrypt
// keys encrypted by Tongsuo's pkcs8 command.
func TestDecryptTongsuoEncryptedKey(t *testing.T) {
	tongsuoAvailable(t)

	tests := []struct {
		name     string
		keyFile  string
		password string
	}{
		{"AES-256-CBC sign key", "sm2_sign_key_aes.pem", certPassword},
		{"SM4-CBC sign key", "sm2_sign_key_sm4.pem", certPassword},
		{"AES-256-CBC enc key", "sm2_enc_key_aes.pem", certPassword},
		{"SM4-CBC enc key", "sm2_enc_key_sm4.pem", certPassword},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyPEM := readCert(t, tc.keyFile)

			decrypted, err := polluxSmx509.DecryptPEMPrivateKey(keyPEM, tc.password)
			if err != nil {
				t.Fatalf("DecryptPEMPrivateKey: %v", err)
			}

			key, err := polluxSm2.ParsePrivateKeyFromPEM(decrypted)
			if err != nil {
				t.Fatalf("ParsePrivateKeyFromPEM: %v", err)
			}
			if key == nil {
				t.Error("key is nil after decrypt+parse")
			}
		})
	}
}
