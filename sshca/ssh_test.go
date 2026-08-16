package sshca

import (
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestGenerateKeyPair(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}

	if keyPair.PrivateKey == nil {
		t.Error("私钥不能为空")
	}

	if keyPair.PublicKey == nil {
		t.Error("公钥不能为空")
	}
}

func TestGenerateED25519KeyPair(t *testing.T) {
	keyPair, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("生成 ED25519 密钥对失败: %v", err)
	}

	if keyPair.PrivateKey == nil {
		t.Error("私钥不能为空")
	}

	if keyPair.PublicKey == nil {
		t.Error("公钥不能为空")
	}

	// 检查密钥类型
	if keyPair.PublicKey.Type() != ssh.KeyAlgoED25519 {
		t.Errorf("期望密钥类型 %s，实际 %s", ssh.KeyAlgoED25519, keyPair.PublicKey.Type())
	}
}

func TestCertificateSigner_SignUserCertificate(t *testing.T) {
	// 生成用户 CA 密钥对
	caKeyPair, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("生成 CA 密钥对失败: %v", err)
	}

	// 创建签名器
	signer, err := NewCertificateSigner(caKeyPair, UserCert, 24*time.Hour)
	if err != nil {
		t.Fatalf("创建签名器失败: %v", err)
	}

	// 生成用户密钥对
	userKeyPair, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("生成用户密钥对失败: %v", err)
	}

	// 创建证书请求
	now := uint64(time.Now().Unix())
	req := &CertificateRequest{
		Type:            UserCert,
		Key:             userKeyPair.PublicKey,
		KeyID:           "testuser",
		ValidPrincipals: []string{"testuser", "admin"},
		ValidAfter:      now,
		ValidBefore:     now + 3600,
		Permissions:     GetDefaultUserPermissions(),
	}

	// 签发证书
	cert, err := signer.SignUserCertificate(req)
	if err != nil {
		t.Fatalf("签发用户证书失败: %v", err)
	}

	if cert == nil {
		t.Fatal("证书不能为空")
		return
	}

	if cert.KeyID != "testuser" {
		t.Errorf("期望 KeyID 'testuser'，实际 '%s'", cert.KeyID)
	}

	if len(cert.ValidPrincipals) != 2 {
		t.Errorf("期望 2 个主体，实际 %d", len(cert.ValidPrincipals))
	}
}

func TestCertificateSigner_SignHostCertificate(t *testing.T) {
	// 生成主机 CA 密钥对
	caKeyPair, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("生成 CA 密钥对失败: %v", err)
	}

	// 创建签名器
	signer, err := NewCertificateSigner(caKeyPair, HostCert, 24*time.Hour)
	if err != nil {
		t.Fatalf("创建签名器失败: %v", err)
	}

	// 生成主机密钥对
	hostKeyPair, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("生成主机密钥对失败: %v", err)
	}

	// 创建证书请求
	now := uint64(time.Now().Unix())
	req := &CertificateRequest{
		Type:            HostCert,
		Key:             hostKeyPair.PublicKey,
		KeyID:           "webserver.example.com",
		ValidPrincipals: []string{"webserver.example.com", "192.168.1.100"},
		ValidAfter:      now,
		ValidBefore:     now + 3600,
		Permissions:     GetDefaultHostPermissions(),
	}

	// 签发证书
	cert, err := signer.SignHostCertificate(req)
	if err != nil {
		t.Fatalf("签发主机证书失败: %v", err)
	}

	if cert == nil {
		t.Fatal("证书不能为空")
		return
	}

	if cert.Type != HostCert {
		t.Errorf("期望证书类型 %d，实际 %d", HostCert, cert.Type)
	}
}

func TestAuthority_CreateAndSignUserCertificate(t *testing.T) {
	// 生成 CA 密钥对
	userCA, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("生成用户 CA 密钥对失败: %v", err)
	}

	hostCA, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("生成主机 CA 密钥对失败: %v", err)
	}

	// 创建授权机构
	auth, err := NewAuthority(userCA, hostCA, 24*time.Hour)
	if err != nil {
		t.Fatalf("创建授权机构失败: %v", err)
	}

	// 生成用户密钥对
	userKeyPair, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("生成用户密钥对失败: %v", err)
	}

	// 创建用户证书请求
	req, err := auth.CreateUserCertificateRequest(
		"testuser",
		userKeyPair.PublicKey,
		[]string{"testuser"},
		1*time.Hour,
		GetDefaultUserPermissions(),
	)
	if err != nil {
		t.Fatalf("创建用户证书请求失败: %v", err)
	}

	// 签发证书
	cert, err := auth.Signer().(*CertificateSigner).SignUserCertificate(req)
	if err != nil {
		t.Fatalf("签发用户证书失败: %v", err)
	}

	// 验证证书
	err = auth.ValidateCertificate(cert.Certificate)
	if err != nil {
		t.Errorf("验证证书失败: %v", err)
	}
}

func TestValidatePrincipals(t *testing.T) {
	tests := []struct {
		name       string
		principals []string
		wantErr    bool
	}{
		{"正常主体", []string{"user", "admin"}, false},
		{"空主体列表", []string{}, true},
		{"包含空字符串", []string{"user", ""}, true},
		{"超长主体", []string{string(make([]byte, 1025))}, true},
		// 字符白名单回归（防 shell 元字符注入）
		{"含分号注入", []string{`root"; rm -rf /`}, true},
		{"含空格", []string{"root user"}, true},
		{"含管道", []string{"root|cat"}, true},
		{"含反引号", []string{"root`whoami`"}, true},
		{"含换行", []string{"root\n"}, true},
		{"点下划线连字符合法", []string{"user.name", "user_name", "user-name"}, false},
		{"含 @ 非法", []string{"user@example"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePrincipals(tt.principals)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePrincipals() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSourceAddresses(t *testing.T) {
	tests := []struct {
		name      string
		addresses []string
		wantErr   bool
	}{
		{"正常 CIDR", []string{"192.168.0.0/16", "10.0.0.0/8"}, false},
		{"正常 IP", []string{"192.168.1.1", "10.0.0.1"}, false},
		// 空串与非规范 CIDR(主机位非零)会产出 OpenSSH 拒收整个列表的
		// source-address("死证书"),必须在签发前拒绝(第二轮审查 M-3/M-4)。
		{"空地址拒绝", []string{""}, true},
		{"主机位非零 CIDR 拒绝", []string{"192.168.1.1/24"}, true},
		{"无效 CIDR", []string{"invalid"}, true},
		{"无效 IP", []string{"999.999.999.999"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSourceAddresses(tt.addresses)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSourceAddresses() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMarshalAuthorizedKey(t *testing.T) {
	keyPair, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}

	authorizedKey := ssh.MarshalAuthorizedKey(keyPair.PublicKey)
	if len(authorizedKey) == 0 {
		t.Error("序列化的公钥不能为空")
	}

	// 验证可以解析回来
	_, _, _, _, err = ssh.ParseAuthorizedKey(authorizedKey)
	if err != nil {
		t.Errorf("解析序列化的公钥失败: %v", err)
	}
}

func TestCertType_String(t *testing.T) {
	tests := []struct {
		c    CertType
		want string
	}{
		{UserCert, "user"},
		{HostCert, "host"},
		{CertType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.c.String(); got != tt.want {
				t.Errorf("CertType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
