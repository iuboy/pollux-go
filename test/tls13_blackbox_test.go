package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	polluxTLS13 "github.com/iuboy/pollux-go/tls13"
)

func mustGenerateTLS13Cert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "tls13-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

func TestBlackBox_TLS13_ServerConfig_EmptyCertFails(t *testing.T) {
	_, err := polluxTLS13.ServerConfig(polluxTLS13.ServerOptions{})
	if err == nil {
		t.Error("ServerConfig with empty Certificates should fail")
	}
}

func TestBlackBox_TLS13_ServerConfig_MinVersion(t *testing.T) {
	cert := mustGenerateTLS13Cert(t)
	cfg, err := polluxTLS13.ServerConfig(polluxTLS13.ServerOptions{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion: got %d, want TLS 1.3", cfg.MinVersion)
	}
}

func TestBlackBox_TLS13_ServerConfig_NextProtos(t *testing.T) {
	cert := mustGenerateTLS13Cert(t)
	cfg, _ := polluxTLS13.ServerConfig(polluxTLS13.ServerOptions{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if len(cfg.NextProtos) != 2 || cfg.NextProtos[0] != "h2" {
		t.Errorf("NextProtos: got %v", cfg.NextProtos)
	}
}

func TestBlackBox_TLS13_ServerConfig_ClientAuth(t *testing.T) {
	cert := mustGenerateTLS13Cert(t)
	pool := x509.NewCertPool()
	cfg, _ := polluxTLS13.ServerConfig(polluxTLS13.ServerOptions{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth: got %d", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs should not be nil")
	}
}

func TestBlackBox_TLS13_ClientConfig_DefaultVerify(t *testing.T) {
	cfg, err := polluxTLS13.ClientConfig(polluxTLS13.ClientOptions{})
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Error("default InsecureSkipVerify should be false")
	}
}

func TestBlackBox_TLS13_ClientConfig_MinVersion(t *testing.T) {
	cfg, _ := polluxTLS13.ClientConfig(polluxTLS13.ClientOptions{})
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion: got %d, want TLS 1.3", cfg.MinVersion)
	}
}

func TestBlackBox_TLS13_ClientConfig_ServerName(t *testing.T) {
	cfg, _ := polluxTLS13.ClientConfig(polluxTLS13.ClientOptions{
		ServerName: "example.com",
	})
	if cfg.ServerName != "example.com" {
		t.Errorf("ServerName: got %q", cfg.ServerName)
	}
}

func TestBlackBox_TLS13_ClientConfig_NextProtos(t *testing.T) {
	cfg, _ := polluxTLS13.ClientConfig(polluxTLS13.ClientOptions{
		NextProtos: []string{"h3"},
	})
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "h3" {
		t.Errorf("NextProtos: got %v", cfg.NextProtos)
	}
}
