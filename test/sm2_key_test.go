package test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	polluxSM2 "github.com/ycq/pollux/sm2"
	polluxSMX509 "github.com/ycq/pollux/smx509"
)

func TestParseSM2PrivateKey(t *testing.T) {
	keyPEM := readCert(t, "sm2_sign_key.pem")

	key, err := polluxSM2.ParsePrivateKeyFromPEM(keyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyFromPEM: %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
	// 验证是 SM2 曲线
	if key.Curve != sm2.P256() {
		t.Error("key is not on SM2 curve")
	}
}

func TestParseSM2PublicKeyFromCert(t *testing.T) {
	certPEM := readCert(t, "sm2_sign_cert.pem")

	cert, err := polluxSMX509.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key type: %T", cert.PublicKey)
	}
	if !polluxSMX509.IsSM2PublicKey(pub) {
		t.Error("public key is not SM2")
	}
}

func TestWriteAndReParseSM2Key(t *testing.T) {
	keyPEM := readCert(t, "sm2_sign_key.pem")

	key, err := polluxSM2.ParsePrivateKeyFromPEM(keyPEM)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// 写入 PEM
	written, err := polluxSM2.WritePrivateKeyToPEM(key)
	if err != nil {
		t.Fatalf("WritePrivateKeyToPEM: %v", err)
	}

	// 重新解析
	key2, err := polluxSM2.ParsePrivateKeyFromPEM(written)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}

	// 验证密钥一致
	if key.D.Cmp(key2.D) != 0 {
		t.Error("keys do not match after round-trip")
	}
}
