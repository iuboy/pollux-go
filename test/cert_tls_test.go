package test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	polluxCert "github.com/iuboy/pollux-go/cert"
	polluxSM2 "github.com/iuboy/pollux-go/sm2"
	polluxSmx509 "github.com/iuboy/pollux-go/smx509"
)

// ========== Helper: 自签名证书生成 ==========

func generateSelfSignedCert(t *testing.T, cn string) (*x509.Certificate, *polluxSM2.PrivateKey, []byte) {
	t.Helper()

	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}

	ecPriv := ecdsa.PrivateKey{PublicKey: priv.PublicKey}
	ecPriv.D = priv.D

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Test Cert"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
	}

	der, err := polluxSmx509.CreateCertificate(tmpl, tmpl, &ecPriv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := polluxSmx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	return cert, priv, der
}

//lint:ignore U1000 retained for future TLS leaf certificate chain tests
func generateTLSLeafCert(t *testing.T, caCert *x509.Certificate, caPriv *polluxSM2.PrivateKey, cn string) (*x509.Certificate, *polluxSM2.PrivateKey, tls.Certificate) {
	t.Helper()

	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	ecPriv := ecdsa.PrivateKey{PublicKey: priv.PublicKey}
	ecPriv.D = priv.D

	caECPub, ok := caCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("CA public key is not *ecdsa.PublicKey")
	}
	caECPriv := ecdsa.PrivateKey{PublicKey: *caECPub}
	caECPriv.D = caPriv.D

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Test Leaf"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}

	der, err := polluxSmx509.CreateCertificate(tmpl, caCert, &ecPriv.PublicKey, &caECPriv)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	cert, err := polluxSmx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}

	return cert, priv, tlsCert
}

// ========== BuildClientTLSConfig ==========

func TestBlackBox_Cert_BuildClientTLSConfig_Basic(t *testing.T) {
	caCert, _, _ := generateSelfSignedCert(t, "client-ca.test")

	rootPool := polluxCert.NewPool()
	rootPool.AddCert(caCert)

	cfg, err := polluxCert.BuildClientTLSConfig(polluxCert.TLSClientOptions{
		ServerName: "client-ca.test",
		Roots:      rootPool,
	})
	if err != nil {
		t.Fatalf("BuildClientTLSConfig: %v", err)
	}

	if cfg.ServerName != "client-ca.test" {
		t.Errorf("ServerName: got %q, want %q", cfg.ServerName, "client-ca.test")
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs should be set")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion: got %d, want >= %d", cfg.MinVersion, tls.VersionTLS12)
	}
}

func TestBlackBox_Cert_BuildClientTLSConfig_WithCertificates(t *testing.T) {
	_, _, leafDER := generateSelfSignedCert(t, "leaf.test")
	leafPriv, _ := polluxSM2.GenerateKey(rand.Reader)
	leafCert := tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafPriv,
	}

	cfg, err := polluxCert.BuildClientTLSConfig(polluxCert.TLSClientOptions{
		Certificates: []tls.Certificate{leafCert},
	})
	if err != nil {
		t.Fatalf("BuildClientTLSConfig: %v", err)
	}

	if len(cfg.Certificates) != 1 {
		t.Errorf("Certificates: got %d, want 1", len(cfg.Certificates))
	}
}

func TestBlackBox_Cert_BuildClientTLSConfig_InsecureSkipVerify(t *testing.T) {
	cfg, err := polluxCert.BuildClientTLSConfig(polluxCert.TLSClientOptions{
		ServerName:         "any.test",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("BuildClientTLSConfig: %v", err)
	}

	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
}

func TestBlackBox_Cert_BuildClientTLSConfig_NoRootsNoInsecure_Fails(t *testing.T) {
	_, err := polluxCert.BuildClientTLSConfig(polluxCert.TLSClientOptions{
		ServerName: "test.example.com",
	})
	if err == nil {
		t.Error("should fail when neither Roots nor InsecureSkipVerify is set")
	}
}

func TestBlackBox_Cert_BuildClientTLSConfig_MinVersion(t *testing.T) {
	caCert, _, _ := generateSelfSignedCert(t, "ca.test")
	rootPool := polluxCert.NewPool()
	rootPool.AddCert(caCert)

	cfg, err := polluxCert.BuildClientTLSConfig(polluxCert.TLSClientOptions{
		Roots:      rootPool,
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("BuildClientTLSConfig: %v", err)
	}

	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion: got %d, want %d", cfg.MinVersion, tls.VersionTLS13)
	}
}

func TestBlackBox_Cert_BuildClientTLSConfig_NextProtos(t *testing.T) {
	caCert, _, _ := generateSelfSignedCert(t, "ca.test")
	rootPool := polluxCert.NewPool()
	rootPool.AddCert(caCert)

	nextProtos := []string{"h2", "http/1.1"}
	cfg, err := polluxCert.BuildClientTLSConfig(polluxCert.TLSClientOptions{
		Roots:      rootPool,
		NextProtos: nextProtos,
	})
	if err != nil {
		t.Fatalf("BuildClientTLSConfig: %v", err)
	}

	if len(cfg.NextProtos) != 2 {
		t.Errorf("NextProtos: got %d, want 2", len(cfg.NextProtos))
	}
}

// ========== BuildServerTLSConfig ==========

func TestBlackBox_Cert_BuildServerTLSConfig_Basic(t *testing.T) {
	_, _, leafDER := generateSelfSignedCert(t, "server.test")
	leafPriv, _ := polluxSM2.GenerateKey(rand.Reader)
	leafCert := tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafPriv,
	}

	cfg, err := polluxCert.BuildServerTLSConfig(polluxCert.TLSProxyServerOptions{
		Certificates: []tls.Certificate{leafCert},
	})
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}

	if len(cfg.Certificates) != 1 {
		t.Errorf("Certificates: got %d, want 1", len(cfg.Certificates))
	}
}

func TestBlackBox_Cert_BuildServerTLSConfig_NoCerts_Fails(t *testing.T) {
	_, err := polluxCert.BuildServerTLSConfig(polluxCert.TLSProxyServerOptions{})
	if err == nil {
		t.Error("should fail without certificates")
	}
}

func TestBlackBox_Cert_BuildServerTLSConfig_ClientAuth(t *testing.T) {
	caCert, _, _ := generateSelfSignedCert(t, "ca.test")
	_, _, leafDER := generateSelfSignedCert(t, "server.test")
	leafPriv, _ := polluxSM2.GenerateKey(rand.Reader)
	leafCert := tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafPriv,
	}

	clientCA := polluxCert.NewPool()
	clientCA.AddCert(caCert)

	cfg, err := polluxCert.BuildServerTLSConfig(polluxCert.TLSProxyServerOptions{
		Certificates: []tls.Certificate{leafCert},
		ClientCAs:    clientCA,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}

	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth: got %d, want %d", cfg.ClientAuth, tls.RequireAndVerifyClientCert)
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs should be set")
	}
}

func TestBlackBox_Cert_BuildServerTLSConfig_MinVersion(t *testing.T) {
	_, _, leafDER := generateSelfSignedCert(t, "server.test")
	leafPriv, _ := polluxSM2.GenerateKey(rand.Reader)
	leafCert := tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafPriv,
	}

	cfg, err := polluxCert.BuildServerTLSConfig(polluxCert.TLSProxyServerOptions{
		Certificates: []tls.Certificate{leafCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}

	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion: got %d, want %d", cfg.MinVersion, tls.VersionTLS13)
	}
}

func TestBlackBox_Cert_BuildServerTLSConfig_NextProtos(t *testing.T) {
	_, _, leafDER := generateSelfSignedCert(t, "server.test")
	leafPriv, _ := polluxSM2.GenerateKey(rand.Reader)
	leafCert := tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafPriv,
	}

	nextProtos := []string{"h2"}
	cfg, err := polluxCert.BuildServerTLSConfig(polluxCert.TLSProxyServerOptions{
		Certificates: []tls.Certificate{leafCert},
		NextProtos:   nextProtos,
	})
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}

	if len(cfg.NextProtos) != 1 {
		t.Errorf("NextProtos: got %d, want 1", len(cfg.NextProtos))
	}
}

// ========== RootCAs SM2 raw DER preservation ==========

func TestBlackBox_Cert_RootCAsPreservesRawDER(t *testing.T) {
	caCert, _, _ := generateSelfSignedCert(t, "sm2-ca.test")

	rootPool := polluxCert.NewPool()
	rootPool.AddCert(caCert)

	cfg, err := polluxCert.BuildClientTLSConfig(polluxCert.TLSClientOptions{
		Roots: rootPool,
	})
	if err != nil {
		t.Fatalf("BuildClientTLSConfig: %v", err)
	}

	if cfg.RootCAs == nil {
		t.Fatal("RootCAs should not be nil")
	}

	rawDER := rootPool.RawDER()
	if len(rawDER) == 0 {
		t.Error("Pool should preserve raw DER")
	}

	for _, der := range rawDER {
		reparsed, err := polluxSmx509.ParseCertificate(der)
		if err != nil {
			t.Errorf("re-parse raw DER with smx509: %v", err)
		}
		if reparsed == nil {
			t.Fatal("reparsed cert should not be nil")
		}
		if reparsed.Subject.CommonName != "sm2-ca.test" {
			t.Errorf("reparsed CN: got %q, want 'sm2-ca.test'", reparsed.Subject.CommonName)
		}
	}
}
