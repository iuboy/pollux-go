package sshca

// 第三轮审查 P2 低危批回归测试:C1 密钥类型白名单、C2 扩展白名单、
// C5 序列号 fail-closed(分支不可注入,不测)、C6 有效期时钟偏差。

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

// TestSignCertificate_RejectsWeakKeyType 锁定 C1:被签公钥类型白名单
// (ssh-dss 类弱类型 / 低于 MinRSAKeyBits 的 RSA / 未知类型一律拒绝)。
func TestSignCertificate_RejectsWeakKeyType(t *testing.T) {
	kp, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewCertificateSigner(kp, UserCert, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// RSA-1024:类型在白名单但位数不足。
	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakPub, err := xssh.NewPublicKey(&weakRSA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.SignCertificate(&CertificateRequest{
		Key:             weakPub,
		KeyID:           "weak",
		ValidPrincipals: []string{"h"},
	}); err == nil {
		t.Fatal("RSA-1024 公钥应被 MinRSAKeyBits 拒绝")
	}

	// 白名单移除 ed25519 后,同类型密钥被拒(白名单可配置且真实生效)。
	// 用副本交换,不原地修改共享 map(避免泄漏到其它测试)。
	saved := AllowedKeyTypes
	narrowed := make(map[string]bool, len(saved))
	for k, v := range saved {
		narrowed[k] = v
	}
	delete(narrowed, "ssh-ed25519")
	AllowedKeyTypes = narrowed
	defer func() { AllowedKeyTypes = saved }()
	if _, err := signer.SignCertificate(&CertificateRequest{
		Key:             kp.PublicKey,
		KeyID:           "ed",
		ValidPrincipals: []string{"h"},
	}); err == nil {
		t.Fatal("白名单移除后 ed25519 公钥应被拒绝")
	}
}

// TestNewCertificateSigner_RejectsWeakCAKey 锁定 C1 的 CA 侧:弱类型/弱强度
// CA 密钥在签名器构造期即被拒绝。
func TestNewCertificateSigner_RejectsWeakCAKey(t *testing.T) {
	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := KeyPairFromRawKey(weakRSA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCertificateSigner(kp, UserCert, time.Hour); err == nil {
		t.Fatal("RSA-1024 CA 密钥应被拒绝")
	}
}

// TestSignCertificate_ExtensionWhitelist 锁定 C2:host 证书拒绝一切请求
// 扩展;user 证书扩展名必须落在 permit-* 白名单内。
func TestSignCertificate_ExtensionWhitelist(t *testing.T) {
	kp, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix())

	hostSigner, err := NewCertificateSigner(kp, HostCert, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hostSigner.SignCertificate(&CertificateRequest{
		Key:             kp.PublicKey,
		KeyID:           "host-ext",
		ValidPrincipals: []string{"h"},
		ValidAfter:      now,
		ValidBefore:     now + 300,
		Extensions:      []Extension{{Name: "permit-pty", Value: ""}},
	}); err == nil {
		t.Fatal("host 证书携带扩展应被拒绝(PROTOCOL.certkeys 禁止)")
	}

	userSigner, err := NewCertificateSigner(kp, UserCert, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := userSigner.SignCertificate(&CertificateRequest{
		Key:             kp.PublicKey,
		KeyID:           "user-bad-ext",
		ValidPrincipals: []string{"h"},
		ValidAfter:      now,
		ValidBefore:     now + 300,
		Extensions:      []Extension{{Name: "totally-custom", Value: "x"}},
	}); err == nil {
		t.Fatal("user 证书未知扩展名应被拒绝")
	}
	cert, err := userSigner.SignCertificate(&CertificateRequest{
		Key:             kp.PublicKey,
		KeyID:           "user-ok-ext",
		ValidPrincipals: []string{"h"},
		ValidAfter:      now,
		ValidBefore:     now + 300,
		Extensions:      []Extension{{Name: "permit-pty", Value: ""}},
	})
	if err != nil {
		t.Fatalf("白名单内的 permit-pty 扩展应被接受: %v", err)
	}
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Fatal("permit-pty 扩展应写入证书")
	}
}

// TestValidateCertificate_ClockSkew 锁定 C6:有效期判定带 60s 时钟偏差
// 容忍——偏差带内(±30s)通过,带外(±120s)拒绝。
func TestValidateCertificate_ClockSkew(t *testing.T) {
	kp, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthority(kp, kp, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(validAfter, validBefore uint64) *xssh.Certificate {
		t.Helper()
		cert, err := auth.Signer().SignCertificate(&CertificateRequest{
			Type:            UserCert,
			Key:             kp.PublicKey,
			KeyID:           "skew",
			ValidPrincipals: []string{"h"},
			ValidAfter:      validAfter,
			ValidBefore:     validBefore,
		})
		if err != nil {
			t.Fatalf("签发证书: %v", err)
		}
		return cert.Certificate
	}

	now := uint64(time.Now().Unix())

	// 激活偏差带内:ValidAfter=now+30 应通过(此前直接"尚未生效")。
	if err := auth.ValidateCertificate(sign(now+30, now+600)); err != nil {
		t.Fatalf("激活偏差带内(30s)应通过: %v", err)
	}
	// 激活偏差带外:ValidAfter=now+120 拒绝。
	if err := auth.ValidateCertificate(sign(now+120, now+600)); err == nil {
		t.Fatal("激活偏差带外(120s)应拒绝")
	}
	// 过期偏差带内:ValidBefore=now-30 应通过。
	if err := auth.ValidateCertificate(sign(now-600, now-30)); err != nil {
		t.Fatalf("过期偏差带内(30s)应通过: %v", err)
	}
	// 过期偏差带外:ValidBefore=now-120 拒绝。
	if err := auth.ValidateCertificate(sign(now-600, now-120)); err == nil {
		t.Fatal("过期偏差带外(120s)应拒绝")
	}
}
