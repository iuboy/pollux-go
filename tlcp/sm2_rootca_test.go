package tlcp

import (
	"encoding/pem"
	"os"
	"testing"
)

// TestConfig_LoadRootCAs_SM2 验证 SM2 CA 证书能被 LoadRootCAsFromPEM 加载。
//
// 回归防护：Go 标准库 crypto/x509 不支持 SM2 椭圆曲线，解析 SM2 证书会返回
// "x509: unsupported elliptic curve"。早期实现用标准库 x509.CertPool 与
// x509.ParseCertificate，导致 SM2 CA 必然加载失败（parsePEMCertificates 返回空、
// AppendCertsFromPEM 返回 false）。修复后 parsePEMCertificates 走 gmsm/smx509，
// createCertPoolAndCertsFromPEM 用 AddCert。本测试用自签名 SM2 CA 锁定该路径。
func TestConfig_LoadRootCAs_SM2(t *testing.T) {
	ca := selfSignCA(t, "sm2-root-ca-test")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})

	c := NewConfig()
	if err := c.LoadRootCAsFromPEM(caPEM, caPEM); err != nil {
		t.Fatalf("LoadRootCAsFromPEM(SM2 CA) err = %v", err)
	}
	if c.SignRootCAs == nil || c.EncRootCAs == nil {
		t.Fatal("SM2 LoadRootCAsFromPEM did not set root pools")
	}
	if len(c.SignRootCertificates) == 0 || len(c.EncRootCertificates) == 0 {
		t.Fatal("SM2 LoadRootCAsFromPEM did not parse raw certificates")
	}
	// 解析出的根证书须携带原始 DER（供 buildSMX509CertPool 从 Raw 重新解析）。
	if len(c.SignRootCertificates[0].Raw) == 0 {
		t.Fatal("parsed SM2 root cert has empty Raw")
	}

	// 文件路径入口同样必须工作（createCertPoolAndCertsFromFile 转发到同一解析路径）。
	dir := t.TempDir()
	caFile := dir + "/sm2_ca.pem"
	if err := os.WriteFile(caFile, caPEM, 0644); err != nil {
		t.Fatalf("write temp CA file: %v", err)
	}
	c2 := NewConfig()
	if err := c2.LoadRootCAs(caFile, caFile); err != nil {
		t.Fatalf("LoadRootCAs(SM2 CA file) err = %v", err)
	}
	if len(c2.SignRootCertificates) == 0 {
		t.Fatal("LoadRootCAs(SM2 CA file) did not parse raw certificates")
	}
}
