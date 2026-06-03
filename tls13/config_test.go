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
