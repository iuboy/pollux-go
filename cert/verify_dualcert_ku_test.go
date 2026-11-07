package cert

// 第四轮安全审计（批 D）Fix 4 回归测试：双证书 enc 侧 KU 接受集统一。
// cert.VerifyDualCertificate 一直接受三 KU 集（keyEncipherment｜
// dataEncipherment｜keyAgreement），smx509.VerifyDualCertSignatures 此前只
// 接受前两者。统一后，仅持 keyAgreement 的 enc 证书在两个入口必须一致通过
// ——本测试在 cert 入口侧锁定该一致性。

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	polluxSM2 "github.com/iuboy/pollux-go/sm2"
	polluxSmx509 "github.com/iuboy/pollux-go/smx509"
)

// buildDualCertPairWithEncKU Cert 侧复刻 smx509/verify_dualcert_ku_test.go
// 的构造：同 CA、同 subject 的 TLCP 双证书对，enc 证书 KeyUsage 由调用方
// 指定，返回根池。
func buildDualCertPairWithEncKU(t *testing.T, encKU x509.KeyUsage) (signCert, encCert *x509.Certificate, roots *Pool) {
	t.Helper()
	caKey, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cert-dual-ku-test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKey:             caKey.Public(),
	}
	caDER, err := polluxSmx509.CreateCertificate(caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatalf("CreateCertificate CA: %v", err)
	}
	caCert, err := ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}
	roots = NewPoolFromCerts(caCert)

	subject := pkix.Name{CommonName: "tlcp-node.test"}

	signKey, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		PublicKey:    signKey.Public(),
	}
	signDER, err := polluxSmx509.CreateCertificate(signTmpl, caCert, signKey.Public(), caKey)
	if err != nil {
		t.Fatalf("CreateCertificate sign: %v", err)
	}
	signCert, err = ParseCertificate(signDER)
	if err != nil {
		t.Fatalf("ParseCertificate sign: %v", err)
	}

	encKey, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     encKU,
		PublicKey:    encKey.Public(),
	}
	encDER, err := polluxSmx509.CreateCertificate(encTmpl, caCert, encKey.Public(), caKey)
	if err != nil {
		t.Fatalf("CreateCertificate enc: %v", err)
	}
	encCert, err = ParseCertificate(encDER)
	if err != nil {
		t.Fatalf("ParseCertificate enc: %v", err)
	}
	return signCert, encCert, roots
}

// TestVerifyDualCertificate_EncCertKeyAgreementOnly 锁定 Fix 4（cert 入口）：
// 仅 keyAgreement 的 enc 证书通过；传统两 KU 集通过；缺失加密用途拒绝。
// 与 smx509 入口（VerifyDualCertSignatures）对同一形状的裁决保持一致。
func TestVerifyDualCertificate_EncCertKeyAgreementOnly(t *testing.T) {
	signCert, encCert, roots := buildDualCertPairWithEncKU(t, x509.KeyUsageKeyAgreement)
	opts := VerifyOptions{Roots: roots}

	if err := VerifyDualCertificate(signCert, encCert, opts, opts); err != nil {
		t.Fatalf("仅 keyAgreement 的 enc 证书应在 cert 入口通过: %v", err)
	}

	sign2, enc2, roots2 := buildDualCertPairWithEncKU(t, x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment)
	if err := VerifyDualCertificate(sign2, enc2, VerifyOptions{Roots: roots2}, VerifyOptions{Roots: roots2}); err != nil {
		t.Fatalf("keyEncipherment+dataEncipherment 的 enc 证书应通过: %v", err)
	}

	sign3, enc3, roots3 := buildDualCertPairWithEncKU(t, x509.KeyUsageDigitalSignature)
	if err := VerifyDualCertificate(sign3, enc3, VerifyOptions{Roots: roots3}, VerifyOptions{Roots: roots3}); err == nil {
		t.Fatal("无任何加密用途的 enc 证书应被拒绝")
	}
}
