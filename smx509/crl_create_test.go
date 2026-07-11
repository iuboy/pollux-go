package smx509

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
)

// TestCreateRevocationList_SM2_FreshTemplate 验证 SM2 CRL 创建支持
// 全新模板（Raw 为空）——这是新建 CRL 的正常场景。
//
// 回归保护：v0.2.3 的 CreateRevocationList 对空 Raw 模板报错
// "cannot convert revocation list with empty Raw field"，导致所有
// SM2 CRL 生成失败。修复用反射字段拷贝替代 DER 往返。
func TestCreateRevocationList_SM2_FreshTemplate(t *testing.T) {
	caKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 CA key: %v", err)
	}
	caPub, err := ExtractPublicKey(caKey)
	if err != nil {
		t.Fatalf("extract public key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
	caTmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-crl-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := CreateCertificate(caTmpl, caTmpl, caPub, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	// 全新模板（Raw 空），含一条撤销记录
	revokedSerial, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: revokedSerial, RevocationTime: time.Now()},
		},
	}
	crlDER, err := CreateRevocationList(tmpl, caCert, caKey)
	if err != nil {
		t.Fatalf("CreateRevocationList with fresh template failed: %v", err)
	}
	if len(crlDER) == 0 {
		t.Fatal("CRL DER is empty")
	}

	// 解析回来验证撤销记录存在
	parsed, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("parse generated CRL: %v", err)
	}
	if len(parsed.RevokedCertificateEntries) != 1 {
		t.Errorf("revoked entries = %d, want 1", len(parsed.RevokedCertificateEntries))
	}
}

// TestCreateRevocationList_SM2_EmptyCRL 验证空 CRL（无撤销记录）也能创建。
func TestCreateRevocationList_SM2_EmptyCRL(t *testing.T) {
	caKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 CA key: %v", err)
	}
	caPub, err := ExtractPublicKey(caKey)
	if err != nil {
		t.Fatalf("extract public key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
	caTmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-empty-crl-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := CreateCertificate(caTmpl, caTmpl, caPub, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	tmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}
	crlDER, err := CreateRevocationList(tmpl, caCert, caKey)
	if err != nil {
		t.Fatalf("CreateRevocationList (empty) failed: %v", err)
	}
	if len(crlDER) == 0 {
		t.Fatal("CRL DER is empty")
	}
}
