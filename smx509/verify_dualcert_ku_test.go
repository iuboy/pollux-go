package smx509

// 第四轮安全审计（批 D）Fix 4 回归测试：双证书 enc 侧 KU 接受集统一。
// smx509.VerifyDualCertSignatures 此前只接受 keyEncipherment｜dataEncipherment，
// cert.VerifyDualCertificate 另接受 keyAgreement——仅持 keyAgreement 的合法
// enc 证书（TLCP ECDHE 套件所需）在两个入口一拒一过。统一为三 KU 集后，
// 两入口对同一证书对的裁决必须一致。

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/sm2"
)

// buildDualCertPairWithEncKU 构造同 CA 签发的 TLCP 双证书对（sign 与 enc 同
// subject），enc 证书的 KeyUsage 由调用方指定，返回根池。
func buildDualCertPairWithEncKU(t *testing.T, encKU x509.KeyUsage) (signCert, encCert *x509.Certificate, rootPool *CertPool) {
	t.Helper()
	caKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dual-ku-test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKey:             caKey.Public(),
	}
	caDER, err := CreateCertificate(caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatalf("CreateCertificate CA: %v", err)
	}
	caCert, err := ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}
	rootPool = NewCertPool()
	rootPool.AddCert(caCert)

	subject := pkix.Name{CommonName: "tlcp-node.test"}

	signKey, err := sm2.GenerateKey(rand.Reader)
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
	signDER, err := CreateCertificate(signTmpl, caCert, signKey.Public(), caKey)
	if err != nil {
		t.Fatalf("CreateCertificate sign: %v", err)
	}
	signCert, err = ParseCertificate(signDER)
	if err != nil {
		t.Fatalf("ParseCertificate sign: %v", err)
	}

	encKey, err := sm2.GenerateKey(rand.Reader)
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
	encDER, err := CreateCertificate(encTmpl, caCert, encKey.Public(), caKey)
	if err != nil {
		t.Fatalf("CreateCertificate enc: %v", err)
	}
	encCert, err = ParseCertificate(encDER)
	if err != nil {
		t.Fatalf("ParseCertificate enc: %v", err)
	}
	return signCert, encCert, rootPool
}

// TestVerifyDualCertSignatures_EncCertKeyAgreementOnly 锁定 Fix 4：仅持
// keyAgreement 的 enc 证书在本入口与 cert 入口一致通过；传统两 KU 集仍
// 通过；完全缺失加密用途仍拒绝。
func TestVerifyDualCertSignatures_EncCertKeyAgreementOnly(t *testing.T) {
	signCert, encCert, rootPool := buildDualCertPairWithEncKU(t, x509.KeyUsageKeyAgreement)
	opts := VerifyOptions{Roots: rootPool}

	// 修复目标：仅 keyAgreement 通过（此前在本入口被拒、cert 入口放行）。
	if err := VerifyDualCertSignatures(signCert, encCert, opts); err != nil {
		t.Fatalf("仅 keyAgreement 的 enc 证书应通过（三 KU 集统一裁决）: %v", err)
	}

	// 传统两 KU 集仍通过。
	sign2, enc2, pool2 := buildDualCertPairWithEncKU(t, x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment)
	if err := VerifyDualCertSignatures(sign2, enc2, VerifyOptions{Roots: pool2}); err != nil {
		t.Fatalf("keyEncipherment+dataEncipherment 的 enc 证书应通过: %v", err)
	}

	// 完全缺失加密用途仍拒绝。
	sign3, enc3, pool3 := buildDualCertPairWithEncKU(t, x509.KeyUsageDigitalSignature)
	if err := VerifyDualCertSignatures(sign3, enc3, VerifyOptions{Roots: pool3}); err == nil {
		t.Fatal("无任何加密用途的 enc 证书应被拒绝")
	}
}
