package tlcp

import (
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// testCertDir 指向 test/cert 下的 SM2 双证书测试材料。
func testCertDir(t *testing.T) string {
	t.Helper()
	// tlcp 包目录的父级即仓库根,test/cert 在其下。
	dir := filepath.Join("..", "test", "cert")
	if _, err := os.Stat(filepath.Join(dir, "rsa_cert.pem")); err != nil {
		t.Fatalf("test cert dir not found at %s: %v", dir, err)
	}
	return dir
}

// TestNewConfig 验证默认值。
func TestNewConfig(t *testing.T) {
	c := NewConfig()
	if c.Version != Version11 {
		t.Errorf("Version = %v, want Version11", c.Version)
	}
	if c.ClientAuth != NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert", c.ClientAuth)
	}
	if c.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = true, want false")
	}
	if len(c.CipherSuites) == 0 {
		t.Error("default CipherSuites empty")
	}
	if c.MinVersion != tls.VersionTLS12 || c.MaxVersion != tls.VersionTLS12 {
		t.Errorf("Min/MaxVersion = %d/%d, want TLS1.2", c.MinVersion, c.MaxVersion)
	}
}

// TestConfig_Validate 覆盖所有校验分支。
func TestConfig_Validate(t *testing.T) {
	signCert, encCert := generateTestCertPair(t)
	valid := func() *Config {
		c := NewConfig()
		c.SignCertificate = signCert
		c.EncCertificate = encCert
		return c
	}

	// 合法配置
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid config Validate() err = %v", err)
	}

	// 版本错误
	c := valid()
	c.Version = Version12
	if err := c.Validate(); !errors.Is(err, ErrInvalidVersion) {
		t.Errorf("Version12 Validate() err = %v, want ErrInvalidVersion", err)
	}

	// 缺签名证书
	c = valid()
	c.SignCertificate = nil
	if err := c.Validate(); !errors.Is(err, ErrMissingSignCertificate) {
		t.Errorf("missing sign cert Validate() err = %v, want ErrMissingSignCertificate", err)
	}

	// 缺加密证书
	c = valid()
	c.EncCertificate = nil
	if err := c.Validate(); !errors.Is(err, ErrMissingEncCertificate) {
		t.Errorf("missing enc cert Validate() err = %v, want ErrMissingEncCertificate", err)
	}

	// 空 cipher 套件
	c = valid()
	c.CipherSuites = nil
	if err := c.Validate(); err == nil {
		t.Error("empty CipherSuites Validate() err = nil, want error")
	}

	// 非国密套件
	c = valid()
	c.CipherSuites = []uint16{0x009C} // TLS_RSA_WITH_AES_128_GCM_SHA256
	if err := c.Validate(); !errors.Is(err, ErrInvalidCipherSuite) {
		t.Errorf("non-national suite Validate() err = %v, want ErrInvalidCipherSuite", err)
	}
}

// TestConfig_Clone 验证深拷贝:修改原件不影响 clone。
func TestConfig_Clone(t *testing.T) {
	signCert, encCert := generateTestCertPair(t)
	c := NewConfig()
	c.ServerName = "example.com"
	c.ClientAuth = RequireAndVerifyClientCert
	c.InsecureSkipVerify = true
	c.SignCertificate = signCert
	c.EncCertificate = encCert
	c.CipherSuites = []uint16{SuiteECDHE_SM2_SM4_GCM_SM3}

	clone := c.Clone()

	if clone.ServerName != c.ServerName || clone.ClientAuth != c.ClientAuth {
		t.Error("Clone did not copy scalar fields")
	}
	if clone.CipherSuites[0] != c.CipherSuites[0] {
		t.Error("Clone did not copy CipherSuites")
	}

	// 深拷贝:篡改原证书字节,clone 不受影响
	origFirst := c.SignCertificate.Certificate[0][0]
	c.SignCertificate.Certificate[0][0] ^= 0xFF
	if clone.SignCertificate.Certificate[0][0] == c.SignCertificate.Certificate[0][0] {
		t.Error("Clone shares certificate byte slice with original (not a deep copy)")
	}
	c.SignCertificate.Certificate[0][0] = origFirst

	// Clone 后独立修改 clone 的 CipherSuites 不影响原件
	clone.CipherSuites[0] = 0xFFFF
	if c.CipherSuites[0] == 0xFFFF {
		t.Error("Clone shares CipherSuites slice with original")
	}
}

// TestConfig_String 验证字符串表示不 panic 且包含关键字段。
func TestConfig_String(t *testing.T) {
	c := NewConfig()
	c.ServerName = "host"
	s := c.String()
	for _, want := range []string{"TLCPConfig", "host"} {
		if !contains(s, want) {
			t.Errorf("String() = %q, missing %q", s, want)
		}
	}
}

// TestConfig_BuildClientConfig 覆盖 sign / enc / rootCAs 分支。
func TestConfig_BuildClientConfig(t *testing.T) {
	signCert, encCert := generateTestCertPair(t)

	// 有签名证书 → Certificates 含 sign
	c := NewConfig()
	c.ServerName = "srv"
	c.SignCertificate = signCert
	cfg, err := c.BuildClientConfig()
	if err != nil {
		t.Fatalf("BuildClientConfig err = %v", err)
	}
	if cfg.ServerName != "srv" {
		t.Errorf("ServerName = %q", cfg.ServerName)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates len = %d, want 1", len(cfg.Certificates))
	}

	// 无 sign 有 enc → Certificates 含 enc
	c = NewConfig()
	c.EncCertificate = encCert
	cfg, _ = c.BuildClientConfig()
	if len(cfg.Certificates) != 1 {
		t.Fatalf("enc-only Certificates len = %d, want 1", len(cfg.Certificates))
	}

	// 两证书都没有 → 无 Certificates
	c = NewConfig()
	cfg, _ = c.BuildClientConfig()
	if len(cfg.Certificates) != 0 {
		t.Errorf("no-cert Certificates len = %d, want 0", len(cfg.Certificates))
	}
}

// TestConfig_BuildServerConfig 覆盖 5 个 ClientAuth 映射 + 证书组装。
func TestConfig_BuildServerConfig(t *testing.T) {
	signCert, encCert := generateTestCertPair(t)
	base := func() *Config {
		c := NewConfig()
		c.SignCertificate = signCert
		c.EncCertificate = encCert
		return c
	}

	auths := []struct {
		src  ClientAuthType
		want tls.ClientAuthType
	}{
		{NoClientCert, tls.NoClientCert},
		{RequestClientCert, tls.RequestClientCert},
		{RequireAnyClientCert, tls.RequireAnyClientCert},
		{VerifyClientCertIfGiven, tls.VerifyClientCertIfGiven},
		{RequireAndVerifyClientCert, tls.RequireAndVerifyClientCert},
	}
	for _, a := range auths {
		c := base()
		c.ClientAuth = a.src
		cfg, err := c.BuildServerConfig()
		if err != nil {
			t.Fatalf("BuildServerConfig(ClientAuth=%v) err = %v", a.src, err)
		}
		if cfg.ClientAuth != a.want {
			t.Errorf("ClientAuth %v → %v, want %v", a.src, cfg.ClientAuth, a.want)
		}
		// 双证书应都被组装进 Certificates
		if len(cfg.Certificates) != 2 {
			t.Errorf("Certificates len = %d, want 2", len(cfg.Certificates))
		}
	}

	// 无证书 → 空 Certificates
	c := NewConfig()
	cfg, _ := c.BuildServerConfig()
	if len(cfg.Certificates) != 0 {
		t.Errorf("no-cert Certificates len = %d, want 0", len(cfg.Certificates))
	}
}

// TestConfig_LoadCertificates 验证从文件加载双证书(成功 + 失败)。
func TestConfig_LoadCertificates(t *testing.T) {
	dir := testCertDir(t)
	c := NewConfig()

	// 成功:sign + enc 证书(不同 issuer 也可加载,LoadCertificates 不校验 issuer)
	err := c.LoadCertificates(
		filepath.Join(dir, "rsa_cert.pem"), filepath.Join(dir, "rsa_key.pem"),
		filepath.Join(dir, "rsa_cert.pem"), filepath.Join(dir, "rsa_key.pem"),
	)
	if err != nil {
		t.Fatalf("LoadCertificates err = %v", err)
	}
	if c.SignCertificate == nil || c.EncCertificate == nil {
		t.Fatal("LoadCertificates did not set certificates")
	}

	// 失败:不存在的签名证书
	c2 := NewConfig()
	err = c2.LoadCertificates(
		"/nonexistent/sign.pem", "/nonexistent/sign.key",
		filepath.Join(dir, "rsa_cert.pem"), filepath.Join(dir, "rsa_key.pem"),
	)
	if err == nil {
		t.Error("LoadCertificates(missing sign) err = nil, want error")
	}

	// 失败:签名证书存在但加密证书缺失
	c3 := NewConfig()
	err = c3.LoadCertificates(
		filepath.Join(dir, "rsa_cert.pem"), filepath.Join(dir, "rsa_key.pem"),
		"/nonexistent/enc.pem", "/nonexistent/enc.key",
	)
	if err == nil {
		t.Error("LoadCertificates(missing enc) err = nil, want error")
	}
}

// TestConfig_LoadCertificatesFromPEM 验证从 PEM 字节加载(成功 + 失败)。
func TestConfig_LoadCertificatesFromPEM(t *testing.T) {
	dir := testCertDir(t)
	signCert, _ := os.ReadFile(filepath.Join(dir, "rsa_cert.pem"))
	signKey, _ := os.ReadFile(filepath.Join(dir, "rsa_key.pem"))
	encCert, _ := os.ReadFile(filepath.Join(dir, "rsa_cert.pem"))
	encKey, _ := os.ReadFile(filepath.Join(dir, "rsa_key.pem"))

	c := NewConfig()
	if err := c.LoadCertificatesFromPEM(signCert, signKey, encCert, encKey); err != nil {
		t.Fatalf("LoadCertificatesFromPEM err = %v", err)
	}
	if c.SignCertificate == nil || c.EncCertificate == nil {
		t.Fatal("certificates not set")
	}

	// 失败:非法 sign PEM
	c2 := NewConfig()
	if err := c2.LoadCertificatesFromPEM([]byte("not a pem"), signKey, encCert, encKey); err == nil {
		t.Error("LoadCertificatesFromPEM(bad sign) err = nil, want error")
	}

	// 失败:合法 sign 但非法 enc PEM
	c3 := NewConfig()
	if err := c3.LoadCertificatesFromPEM(signCert, signKey, []byte("not a pem"), encKey); err == nil {
		t.Error("LoadCertificatesFromPEM(bad enc) err = nil, want error")
	}
}

// TestConfig_LoadRootCAs 验证从文件加载根 CA 池(成功 + 失败)。
func TestConfig_LoadRootCAs(t *testing.T) {
	dir := testCertDir(t)
	signCertFile := filepath.Join(dir, "rsa_cert.pem")
	encCertFile := filepath.Join(dir, "rsa_cert.pem")

	c := NewConfig()
	if err := c.LoadRootCAs(signCertFile, encCertFile); err != nil {
		t.Fatalf("LoadRootCAs err = %v", err)
	}
	if c.SignRootCAs == nil || c.EncRootCAs == nil {
		t.Fatal("LoadRootCAs did not set root pools")
	}
	if len(c.SignRootCertificates) == 0 || len(c.EncRootCertificates) == 0 {
		t.Fatal("LoadRootCAs did not parse raw certificates")
	}

	// 失败:不存在的 sign root
	c2 := NewConfig()
	if err := c2.LoadRootCAs("/nonexistent/sign.pem", encCertFile); err == nil {
		t.Error("LoadRootCAs(missing sign) err = nil, want error")
	}

	// 失败:合法 sign 但缺失 enc root
	c3 := NewConfig()
	if err := c3.LoadRootCAs(signCertFile, "/nonexistent/enc.pem"); err == nil {
		t.Error("LoadRootCAs(missing enc) err = nil, want error")
	}
}

// TestConfig_LoadRootCAsFromPEM 验证从 PEM 字节加载根 CA 池(成功 + 失败)。
func TestConfig_LoadRootCAsFromPEM(t *testing.T) {
	dir := testCertDir(t)
	signPEM, _ := os.ReadFile(filepath.Join(dir, "rsa_cert.pem"))
	encPEM, _ := os.ReadFile(filepath.Join(dir, "rsa_cert.pem"))

	c := NewConfig()
	if err := c.LoadRootCAsFromPEM(signPEM, encPEM); err != nil {
		t.Fatalf("LoadRootCAsFromPEM err = %v", err)
	}
	if c.SignRootCAs == nil {
		t.Fatal("SignRootCAs not set")
	}

	// 失败:非法 sign PEM
	c2 := NewConfig()
	if err := c2.LoadRootCAsFromPEM([]byte("garbage"), encPEM); err == nil {
		t.Error("LoadRootCAsFromPEM(bad sign) err = nil, want error")
	}

	// 失败:合法 sign 但非法 enc PEM
	c3 := NewConfig()
	if err := c3.LoadRootCAsFromPEM(signPEM, []byte("garbage")); err == nil {
		t.Error("LoadRootCAsFromPEM(bad enc) err = nil, want error")
	}
}

// TestParsePEMCertificates_NonCertificateBlock 验证非 CERTIFICATE 类型块被跳过。
func TestParsePEMCertificates_NonCertificateBlock(t *testing.T) {
	// 构造一个只含 PRIVATE KEY 块的 PEM
	keyPEM := []byte(`-----BEGIN PRIVATE KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEdummiesubstringnotrealbutlengthok
-----END PRIVATE KEY-----
`)
	certs := parsePEMCertificates(keyPEM)
	if len(certs) != 0 {
		t.Errorf("parsePEMCertificates(private key block) = %d certs, want 0", len(certs))
	}
}

// TestConfigToNative_Nil 验证 nil 配置返回错误。
func TestConfigToNative_Nil(t *testing.T) {
	if _, err := configToNative(nil, false); err == nil {
		t.Error("configToNative(nil) err = nil, want error")
	}
}

// TestConfigToNative_WithRootCerts 验证根证书被收集到 rootCAs DER 列表。
func TestConfigToNative_WithRootCerts(t *testing.T) {
	dir := testCertDir(t)
	signPEM, _ := os.ReadFile(filepath.Join(dir, "rsa_cert.pem"))
	encPEM, _ := os.ReadFile(filepath.Join(dir, "rsa_cert.pem"))

	c := NewConfig()
	if err := c.LoadRootCAsFromPEM(signPEM, encPEM); err != nil {
		t.Fatalf("LoadRootCAsFromPEM err: %v", err)
	}
	c.ClientCACertificates = c.SignRootCertificates

	nc, err := configToNative(c, false)
	if err != nil {
		t.Fatalf("configToNative err: %v", err)
	}
	if len(nc.rootCAs) == 0 {
		t.Error("nc.rootCAs empty, want populated DER list")
	}
}
