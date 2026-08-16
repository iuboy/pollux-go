package sshca

// 安全加固回归测试(第二轮审查 M1/M2 修复)。

import (
	"strings"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

// TestValidateCertificate_ForceCommandAccepted 锁定 M1:x/crypto 的
// CertChecker 要求非 source-address 的 critical option 出现在
// SupportedCriticalOptions 白名单内;历史实现空切片导致所有带
// force-command 的合法证书在到达手写白名单前就被误拒(白名单成死代码)。
func TestValidateCertificate_ForceCommandAccepted(t *testing.T) {
	kp, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthority(kp, kp, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	now := uint64(time.Now().Unix())
	cert, err := auth.Signer().SignCertificate(&CertificateRequest{
		Type:            UserCert,
		Key:             kp.PublicKey,
		KeyID:           "fc-user",
		ValidPrincipals: []string{"fc-host"},
		ValidAfter:      now,
		ValidBefore:     now + 1800,
		CriticalOptions: []CriticalOption{{Name: "force-command", Value: "/usr/bin/backup"}},
	})
	if err != nil {
		t.Fatalf("签发 force-command 证书: %v", err)
	}
	if err := auth.ValidateCertificate(cert.Certificate); err != nil {
		t.Fatalf("本 CA 签发的 force-command 证书应通过验证: %v", err)
	}
}

// TestSignCertificate_RejectsBadCriticalOptions 锁定 M2:签发边界应用
// 与验证侧一致的白名单(历史实现原样拷贝,可签出空值 force-command、
// 非法 source-address、未知 option——过不了自己验证或被 sshd 拒收)。
func TestSignCertificate_RejectsBadCriticalOptions(t *testing.T) {
	kp, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewCertificateSigner(kp, UserCert, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix())

	mkReq := func(opts []CriticalOption) *CertificateRequest {
		return &CertificateRequest{
			Type: UserCert, Key: kp.PublicKey, KeyID: "bad-co",
			ValidPrincipals: []string{"h"}, ValidAfter: now, ValidBefore: now + 600,
			CriticalOptions: opts,
		}
	}

	if _, err := signer.SignCertificate(mkReq([]CriticalOption{{Name: "force-command", Value: ""}})); err == nil {
		t.Fatal("空值 force-command 应拒绝签发")
	}
	if _, err := signer.SignCertificate(mkReq([]CriticalOption{{Name: "source-address", Value: "192.168.1.1/24"}})); err == nil {
		t.Fatal("非规范 CIDR 的 source-address 应拒绝签发")
	}
	_, err = signer.SignCertificate(mkReq([]CriticalOption{{Name: "evil-option", Value: "x"}}))
	if err == nil || !strings.Contains(err.Error(), "未识别") {
		t.Fatalf("未知 critical option 应拒绝签发: %v", err)
	}
}

// TestNewCertificateSigner_RejectsBadCertType 锁定 L5:非法 CertType
// 会被原样写入证书 wire 字段,必须在构造器拦截。
func TestNewCertificateSigner_RejectsBadCertType(t *testing.T) {
	kp, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCertificateSigner(kp, CertType(99), time.Hour); err == nil {
		t.Fatal("非法 certType 应在构造器被拒绝")
	}
}

// TestBuildKRL_RejectsInvalidCAWire 锁定 L1:非法 CA wire 的 KRL 会被
// OpenSSH 整体拒收,sshd 对 KRL 解析错误的处理是拒绝所有密钥。
func TestBuildKRL_RejectsInvalidCAWire(t *testing.T) {
	if _, err := BuildKRL([]byte("not-a-wire"), []uint64{1}, ""); err == nil {
		t.Fatal("非法 CA wire 应拒绝生成 KRL")
	}
}

// TestAuthorityWithRevocation_RejectsRevokedCert 锁定 L4:注入吊销谓词后
// 已吊销证书在 ValidateCertificate 即被拒(此前仅依赖消费端 sshd 兜底)。
func TestAuthorityWithRevocation_RejectsRevokedCert(t *testing.T) {
	kp, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthorityWithRevocation(kp, kp, time.Hour, func(c *xssh.Certificate) bool {
		return c.KeyId == "rev-check" // 按 KeyId 吊销(不修改已签名字段)
	})
	if err != nil {
		t.Fatal(err)
	}

	now := uint64(time.Now().Unix())
	cert, err := auth.Signer().SignCertificate(&CertificateRequest{
		Type: UserCert, Key: kp.PublicKey, KeyID: "rev-check",
		ValidPrincipals: []string{"h"}, ValidAfter: now, ValidBefore: now + 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	// KeyId 命中吊销谓词。
	if err := auth.ValidateCertificate(cert.Certificate); err == nil {
		t.Fatal("命中吊销谓词的证书应被 ValidateCertificate 拒绝")
	}
	// 未命中的证书(重新签发一个不同 KeyId)通过。
	cert2, err := auth.Signer().SignCertificate(&CertificateRequest{
		Type: UserCert, Key: kp.PublicKey, KeyID: "rev-ok",
		ValidPrincipals: []string{"h"}, ValidAfter: now, ValidBefore: now + 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidateCertificate(cert2.Certificate); err != nil {
		t.Fatalf("未吊销证书应通过: %v", err)
	}
}

// TestSignCertificate_TypeMismatchRejected 锁定 I3:req.Type 与签名器类型
// 不一致必须报错(此前 user 签名器静默把 HostCert 请求签成 user 证书)。
func TestSignCertificate_TypeMismatchRejected(t *testing.T) {
	kp, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	userSigner, err := NewCertificateSigner(kp, UserCert, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix())
	_, err = userSigner.SignCertificate(&CertificateRequest{
		Type: HostCert, // user 签名器收到 host 请求
		Key:  kp.PublicKey, KeyID: "type-mismatch",
		ValidPrincipals: []string{"h"}, ValidAfter: now, ValidBefore: now + 600,
	})
	if err == nil {
		t.Fatal("Type=HostCert 的请求交给 user 签名器应报错")
	}
}
