package tls13

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func generateTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}

func TestServerConfig_RequiresCertificate(t *testing.T) {
	_, err := ServerConfig(ServerOptions{})
	if err == nil {
		t.Error("expected error for empty certificates")
	}
}

func TestServerConfig_MinVersionTLS13(t *testing.T) {
	cfg, err := ServerConfig(ServerOptions{
		Certificates: []tls.Certificate{generateTestCert(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion: got %d, want %d", cfg.MinVersion, tls.VersionTLS13)
	}
}

func TestServerConfig_NextProtos(t *testing.T) {
	cfg, err := ServerConfig(ServerOptions{
		Certificates: []tls.Certificate{generateTestCert(t)},
		NextProtos:   []string{"h3", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.NextProtos) != 2 || cfg.NextProtos[0] != "h3" {
		t.Errorf("NextProtos: got %v", cfg.NextProtos)
	}
}

func TestServerConfig_ClientAuth(t *testing.T) {
	pool := x509.NewCertPool()
	cfg, err := ServerConfig(ServerOptions{
		Certificates: []tls.Certificate{generateTestCert(t)},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth: got %d", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs should not be nil")
	}
}

func TestServerConfig_ClientAuthRequireVerifyWithoutClientCAsFails(t *testing.T) {
	_, err := ServerConfig(ServerOptions{
		Certificates: []tls.Certificate{generateTestCert(t)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	if err == nil {
		t.Fatal("expected error when RequireAndVerifyClientCert has no ClientCAs")
	}
}

func TestServerConfig_RequireAnyClientCertWithoutClientCAs(t *testing.T) {
	cfg, err := ServerConfig(ServerOptions{
		Certificates: []tls.Certificate{generateTestCert(t)},
		ClientAuth:   tls.RequireAnyClientCert,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequireAnyClientCert {
		t.Errorf("ClientAuth: got %d", cfg.ClientAuth)
	}
}

func TestClientConfig_DefaultVerifyEnabled(t *testing.T) {
	cfg, err := ClientConfig(ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false by default")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion: got %d, want %d", cfg.MinVersion, tls.VersionTLS13)
	}
}

func TestClientConfig_InsecureSkipVerifyExplicit(t *testing.T) {
	cfg, err := ClientConfig(ClientOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true when explicitly set")
	}
}

func TestClientConfig_ServerName(t *testing.T) {
	cfg, err := ClientConfig(ClientOptions{
		ServerName: "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "example.com" {
		t.Errorf("ServerName: got %q, want %q", cfg.ServerName, "example.com")
	}
}

func TestClientConfig_CertificatesAndRoots(t *testing.T) {
	cert := generateTestCert(t)
	pool := x509.NewCertPool()
	cfg, err := ClientConfig(ClientOptions{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certificates) != 1 {
		t.Error("Certificates not set")
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs should not be nil")
	}
}

// TestCipherSuitesOption 锁定遗留项 A6:CipherSuites 选项仅接受 TLS 1.3
// 套件(非 1.3 套件 ID 会静默清空偏好集);空列表走 stdlib 默认。
func TestCipherSuitesOption(t *testing.T) {
	cert := tls.Certificate{Certificate: [][]byte{{1}}}
	for _, bad := range []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, 0x00FF} {
		if _, err := ServerConfig(ServerOptions{Certificates: []tls.Certificate{cert}, CipherSuites: []uint16{bad}}); err == nil {
			t.Errorf("服务端非 TLS1.3 套件 %#04x 应被拒绝", bad)
		}
		if _, err := ClientConfig(ClientOptions{CipherSuites: []uint16{bad}}); err == nil {
			t.Errorf("客户端非 TLS1.3 套件 %#04x 应被拒绝", bad)
		}
	}
	cfg, err := ServerConfig(ServerOptions{Certificates: []tls.Certificate{cert}, CipherSuites: []uint16{tls.TLS_AES_256_GCM_SHA384}})
	if err != nil {
		t.Fatalf("合法 TLS1.3 套件应通过: %v", err)
	}
	if len(cfg.CipherSuites) != 1 || cfg.CipherSuites[0] != tls.TLS_AES_256_GCM_SHA384 {
		t.Fatalf("套件应写入 tls.Config, got %v", cfg.CipherSuites)
	}
	def, err := ServerConfig(ServerOptions{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("空列表(默认)应通过: %v", err)
	}
	if def.CipherSuites != nil {
		t.Fatal("空列表应保持 nil(stb 默认序)")
	}
}
