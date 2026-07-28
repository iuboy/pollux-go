package sm2

import (
	"encoding/pem"
	"strings"
	"testing"
)

func TestParsePrivateKeyFromPEM(t *testing.T) {
	priv, err := GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	pemData, err := WritePrivateKeyToPEM(priv)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParsePrivateKeyFromPEM(pemData)
	if err != nil {
		t.Fatalf("ParsePrivateKeyFromPEM: %v", err)
	}

	if parsed.D.Cmp(priv.D) != 0 {
		t.Error("parsed key does not match original")
	}
}

func TestParsePrivateKeyFromPEMInvalid(t *testing.T) {
	tests := []string{
		"not pem data",
		"-----BEGIN EC PRIVATE KEY-----\ninvalid base64\n-----END EC PRIVATE KEY-----",
		"-----BEGIN WRONG TYPE-----\nMHcCAQEEIK8+bSTY0KKlUEGFHUWylJvCkQ0s6jYiDk4kxWykK5oAoGCCqBHM9VAYI\n-----END WRONG TYPE-----",
	}

	for _, tt := range tests {
		_, err := ParsePrivateKeyFromPEM([]byte(tt))
		if err == nil {
			t.Errorf("ParsePrivateKeyFromPEM(%q) should error", tt)
		}
	}
}

func TestParsePrivateKeyFromPEMEncrypted(t *testing.T) {
	priv, err := GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	// Create encrypted PEM.
	// 用 PrivateKeyToBytesSecure（替代已移除的 PrivateKeyToBytes），Destroy 清零敏感内存。
	skb, err := PrivateKeyToBytesSecure(priv)
	if err != nil {
		t.Fatalf("PrivateKeyToBytesSecure: %v", err)
	}
	defer skb.Destroy()
	privBytes := skb.Data()
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  "AES-256-CBC,0123456789ABCDEF0123456789ABCDEF",
		},
	}
	pemData := pem.EncodeToMemory(block)

	// Should fail without decryption
	_, err = ParsePrivateKeyFromPEM(pemData)
	if err == nil {
		t.Error("encrypted PEM should fail to parse without password")
	}
}

func TestParsePublicKeyFromPEM(t *testing.T) {
	priv, err := GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	pemData, err := WritePublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParsePublicKeyFromPEM(pemData)
	if err != nil {
		t.Fatalf("ParsePublicKeyFromPEM: %v", err)
	}

	if parsed.X.Cmp(priv.PublicKey.X) != 0 || parsed.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Error("parsed key does not match original")
	}
}

func TestParsePublicKeyFromPEMInvalid(t *testing.T) {
	tests := []string{
		"not pem data",
		"-----BEGIN PUBLIC KEY-----\ninvalid base64\n-----END PUBLIC KEY-----",
		"-----BEGIN WRONG TYPE-----\nMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEEVs/o5+UJHYCSA0U9B8DhE\n-----END WRONG TYPE-----",
	}

	for _, tt := range tests {
		_, err := ParsePublicKeyFromPEM([]byte(tt))
		if err == nil {
			t.Errorf("ParsePublicKeyFromPEM(%q) should error", tt)
		}
	}
}

func TestWritePrivateKeyToPEM(t *testing.T) {
	priv, err := GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	pemData, err := WritePrivateKeyToPEM(priv)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(string(pemData), "-----BEGIN PRIVATE KEY-----") {
		t.Error("PEM header missing")
	}
	if !strings.HasSuffix(string(pemData), "-----END PRIVATE KEY-----\n") {
		t.Error("PEM footer missing")
	}

	// Should be parseable
	parsed, err := ParsePrivateKeyFromPEM(pemData)
	if err != nil {
		t.Errorf("round-trip failed: %v", err)
	}
	if parsed.D.Cmp(priv.D) != 0 {
		t.Error("round-trip key mismatch")
	}
}

func TestWritePublicKeyToPEM(t *testing.T) {
	priv, err := GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	pemData, err := WritePublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(string(pemData), "-----BEGIN PUBLIC KEY-----") {
		t.Error("PEM header missing")
	}
	if !strings.HasSuffix(string(pemData), "-----END PUBLIC KEY-----\n") {
		t.Error("PEM footer missing")
	}

	// Should be parseable
	parsed, err := ParsePublicKeyFromPEM(pemData)
	if err != nil {
		t.Errorf("round-trip failed: %v", err)
	}
	if parsed.X.Cmp(priv.PublicKey.X) != 0 || parsed.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Error("round-trip key mismatch")
	}
}
