package smx509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
)

func TestCreateCertificateRequest_SM2(t *testing.T) {
	priv, err := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sm2Priv := new(sm2.PrivateKey)
	if _, err := sm2Priv.FromECPrivateKey(priv); err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "sm2-csr-test"},
		DNSNames: []string{"localhost"},
	}

	der, err := CreateCertificateRequest(tmpl, sm2Priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest SM2: %v", err)
	}
	if len(der) == 0 {
		t.Error("CSR DER should not be empty")
	}

	csr, err := ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if csr.Subject.CommonName != "sm2-csr-test" {
		t.Errorf("CommonName: got %q, want %q", csr.Subject.CommonName, "sm2-csr-test")
	}
}

func TestCreateCertificateRequest_RSA(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "rsa-csr-test"},
	}

	der, err := CreateCertificateRequest(tmpl, rsaPriv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest RSA: %v", err)
	}

	csr, err := ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if csr.Subject.CommonName != "rsa-csr-test" {
		t.Errorf("CommonName: got %q, want %q", csr.Subject.CommonName, "rsa-csr-test")
	}
}

func TestCheckCertificateRequestSignature(t *testing.T) {
	priv, err := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sm2Priv := new(sm2.PrivateKey)
	_, _ = sm2Priv.FromECPrivateKey(priv)

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "sig-check-test"},
	}

	der, err := CreateCertificateRequest(tmpl, sm2Priv)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}

	if err := CheckCertificateRequestSignature(csr); err != nil {
		t.Errorf("CheckCertificateRequestSignature: %v", err)
	}
}

// TestCheckCertificateRequestSignature_CorruptedECDSA 验证 ECDSA CSR 的
// 破坏签名被正确拒绝（回归保护）。
//
// 回归背景：CheckCertificateRequestSignature 对所有 stdlib 失败做 gmsm 重试，
// 但 gmsm 重试走 DER 往返（Raw 含原始有效签名），会从 DER 恢复有效签名，
// 掩盖内存中破坏的 Signature 字段 → 破坏签名被误判为有效。修复仅对
// ErrUnsupportedAlgorithm（SM2 OID）重试，其他错误直接返回。
func TestCheckCertificateRequestSignature_CorruptedECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "corrupted"}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	// 破坏内存中的签名字节
	csr.Signature = []byte{0x00, 0x01, 0x02}
	if err := CheckCertificateRequestSignature(csr); err == nil {
		t.Error("corrupted ECDSA CSR signature should be rejected, got nil")
	}
}

func TestParseCertificatePEM(t *testing.T) {
	priv, err := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sm2Priv := new(sm2.PrivateKey)
	_, _ = sm2Priv.FromECPrivateKey(priv)

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "pem-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := CreateCertificate(tmpl, tmpl, &priv.PublicKey, sm2Priv)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if pemData == nil {
		t.Fatal("pem.EncodeToMemory returned nil")
	}

	cert, err := ParseCertificatePEM(pemData)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	if cert.Subject.CommonName != "pem-test" {
		t.Errorf("CommonName: got %q, want %q", cert.Subject.CommonName, "pem-test")
	}
}

func TestParseCertificatePEM_Invalid(t *testing.T) {
	_, err := ParseCertificatePEM([]byte("not PEM data"))
	if err == nil {
		t.Error("should reject invalid PEM data")
	}
}

func TestVerify_NilCert(t *testing.T) {
	err := Verify(nil, VerifyOptions{})
	if err == nil {
		t.Error("should reject nil certificate")
	}
}

func TestVerifyDualCerts_NilArgs(t *testing.T) {
	err := VerifyDualCerts(nil, nil)
	if err == nil {
		t.Error("should reject nil certificates")
	}
}

func TestVerifyDualCerts_MismatchedCA(t *testing.T) {
	// 两个不同 CA 签发的证书
	priv1, _ := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	sm2Priv1 := new(sm2.PrivateKey)
	_, _ = sm2Priv1.FromECPrivateKey(priv1)

	priv2, _ := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	sm2Priv2 := new(sm2.PrivateKey)
	_, _ = sm2Priv2.FromECPrivateKey(priv2)

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	signTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "sign"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	signDER, _ := CreateCertificate(signTmpl, signTmpl, &priv1.PublicKey, sm2Priv1)
	signCert, _ := x509.ParseCertificate(signDER)

	encTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: "enc"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
	}
	encDER, _ := CreateCertificate(encTmpl, encTmpl, &priv2.PublicKey, sm2Priv2)
	encCert, _ := x509.ParseCertificate(encDER)

	err := VerifyDualCerts(signCert, encCert)
	if err == nil {
		t.Error("should reject mismatched CA certificates")
	}
}

func TestVerifyDualCerts_InvalidKeyUsage(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	sm2Priv := new(sm2.PrivateKey)
	_, _ = sm2Priv.FromECPrivateKey(priv)

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// 两个证书都只有 KeyUsageDigitalSignature，加密证书缺少 keyEncipherment
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "both-sign"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, _ := CreateCertificate(tmpl, tmpl, &priv.PublicKey, sm2Priv)
	cert, _ := x509.ParseCertificate(der)

	err := VerifyDualCerts(cert, cert)
	if err == nil {
		t.Error("should reject certs with invalid key usage")
	}
}
