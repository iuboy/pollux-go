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
	polluxTLCP "github.com/iuboy/pollux-go/tlcp"
)

// ========== Helper: TLCP 双证书生成 ==========

func generateTLCPDualCert(t *testing.T, signCN, encCN string) (*polluxCert.DualCertificate, *x509.Certificate, *x509.Certificate) {
	t.Helper()

	caPriv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caECPriv := ecdsa.PrivateKey{PublicKey: caPriv.PublicKey}
	caECPriv.D = caPriv.D

	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "TLCP CA", Organization: []string{"TLCP Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := polluxSmx509.CreateCertificate(caTmpl, caTmpl, &caECPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := polluxSmx509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	signPriv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sign key: %v", err)
	}
	signECPriv := ecdsa.PrivateKey{PublicKey: signPriv.PublicKey}
	signECPriv.D = signPriv.D

	signSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	signTmpl := &x509.Certificate{
		SerialNumber: signSerial,
		Subject:      pkix.Name{CommonName: signCN, Organization: []string{"TLCP Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{signCN},
	}
	signDER, err := polluxSmx509.CreateCertificate(signTmpl, caCert, &signECPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("create sign cert: %v", err)
	}

	encPriv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate enc key: %v", err)
	}
	encECPriv := ecdsa.PrivateKey{PublicKey: encPriv.PublicKey}
	encECPriv.D = encPriv.D

	encSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	encTmpl := &x509.Certificate{
		SerialNumber: encSerial,
		Subject:      pkix.Name{CommonName: encCN, Organization: []string{"TLCP Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{encCN},
	}
	encDER, err := polluxSmx509.CreateCertificate(encTmpl, caCert, &encECPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("create enc cert: %v", err)
	}

	dual := &polluxCert.DualCertificate{
		Sign: tls.Certificate{
			Certificate: [][]byte{signDER},
			PrivateKey:  signPriv,
		},
		Enc: tls.Certificate{
			Certificate: [][]byte{encDER},
			PrivateKey:  encPriv,
		},
	}

	return dual, caCert, signTmpl
}

// ========== BuildTLCPConfig ==========

func TestBlackBox_Cert_BuildTLCPConfig_Basic(t *testing.T) {
	dual, caCert, _ := generateTLCPDualCert(t, "sign.test", "enc.test")

	signRoots := polluxCert.NewPool()
	signRoots.AddCert(caCert)

	encRoots := polluxCert.NewPool()
	encRoots.AddCert(caCert)

	cfg, err := polluxCert.BuildTLCPConfig(polluxCert.TLCPProxyOptions{
		Certificates: dual,
		SignRoots:    signRoots,
		EncRoots:     encRoots,
	})
	if err != nil {
		t.Fatalf("BuildTLCPConfig: %v", err)
	}

	if cfg.SignCertificate == nil {
		t.Error("SignCertificate should be set")
	}
	if cfg.EncCertificate == nil {
		t.Error("EncCertificate should be set")
	}
	if cfg.SignRootCAs == nil {
		t.Error("SignRootCAs should be set")
	}
	if cfg.EncRootCAs == nil {
		t.Error("EncRootCAs should be set")
	}
}

func TestBlackBox_Cert_BuildTLCPConfig_NoDualCert_Fails(t *testing.T) {
	_, err := polluxCert.BuildTLCPConfig(polluxCert.TLCPProxyOptions{})
	if err == nil {
		t.Error("should fail without dual certificate")
	}
}

func TestBlackBox_Cert_BuildTLCPConfig_ServerName(t *testing.T) {
	dual, caCert, _ := generateTLCPDualCert(t, "sign.test", "enc.test")

	signRoots := polluxCert.NewPool()
	signRoots.AddCert(caCert)
	encRoots := polluxCert.NewPool()
	encRoots.AddCert(caCert)

	cfg, err := polluxCert.BuildTLCPConfig(polluxCert.TLCPProxyOptions{
		Certificates: dual,
		SignRoots:    signRoots,
		EncRoots:     encRoots,
		ServerName:   "tlcp.example.com",
	})
	if err != nil {
		t.Fatalf("BuildTLCPConfig: %v", err)
	}

	if cfg.ServerName != "tlcp.example.com" {
		t.Errorf("ServerName: got %q, want %q", cfg.ServerName, "tlcp.example.com")
	}
}

func TestBlackBox_Cert_BuildTLCPConfig_CipherSuites(t *testing.T) {
	dual, caCert, _ := generateTLCPDualCert(t, "sign.test", "enc.test")

	signRoots := polluxCert.NewPool()
	signRoots.AddCert(caCert)
	encRoots := polluxCert.NewPool()
	encRoots.AddCert(caCert)

	customSuites := []uint16{
		polluxTLCP.SuiteECDHE_SM2_SM4_GCM_SM3,
	}

	cfg, err := polluxCert.BuildTLCPConfig(polluxCert.TLCPProxyOptions{
		Certificates: dual,
		SignRoots:    signRoots,
		EncRoots:     encRoots,
		CipherSuites: customSuites,
	})
	if err != nil {
		t.Fatalf("BuildTLCPConfig: %v", err)
	}

	if len(cfg.CipherSuites) != 1 {
		t.Errorf("CipherSuites: got %d, want 1", len(cfg.CipherSuites))
	}
	if cfg.CipherSuites[0] != polluxTLCP.SuiteECDHE_SM2_SM4_GCM_SM3 {
		t.Errorf("CipherSuite: got 0x%04X, want 0xE051", cfg.CipherSuites[0])
	}
}

func TestBlackBox_Cert_BuildTLCPConfig_DefaultCipherSuites(t *testing.T) {
	dual, caCert, _ := generateTLCPDualCert(t, "sign.test", "enc.test")

	signRoots := polluxCert.NewPool()
	signRoots.AddCert(caCert)
	encRoots := polluxCert.NewPool()
	encRoots.AddCert(caCert)

	cfg, err := polluxCert.BuildTLCPConfig(polluxCert.TLCPProxyOptions{
		Certificates: dual,
		SignRoots:    signRoots,
		EncRoots:     encRoots,
	})
	if err != nil {
		t.Fatalf("BuildTLCPConfig: %v", err)
	}

	if len(cfg.CipherSuites) == 0 {
		t.Error("CipherSuites should default to TLCP cipher suites")
	}
}

func TestBlackBox_Cert_BuildTLCPConfig_ClientAuth(t *testing.T) {
	dual, caCert, _ := generateTLCPDualCert(t, "sign.test", "enc.test")

	signRoots := polluxCert.NewPool()
	signRoots.AddCert(caCert)
	encRoots := polluxCert.NewPool()
	encRoots.AddCert(caCert)

	clientCAs := polluxCert.NewPool()
	clientCAs.AddCert(caCert)

	cfg, err := polluxCert.BuildTLCPConfig(polluxCert.TLCPProxyOptions{
		Certificates: dual,
		SignRoots:    signRoots,
		EncRoots:     encRoots,
		ClientAuth:   polluxTLCP.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	})
	if err != nil {
		t.Fatalf("BuildTLCPConfig: %v", err)
	}

	if cfg.ClientAuth != polluxTLCP.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth: got %d, want %d", cfg.ClientAuth, polluxTLCP.RequireAndVerifyClientCert)
	}
	if cfg.ClientCACertificates == nil {
		t.Error("ClientCACertificates should be set")
	}
}

func TestBlackBox_Cert_BuildTLCPConfig_MinVersion(t *testing.T) {
	dual, caCert, _ := generateTLCPDualCert(t, "sign.test", "enc.test")

	signRoots := polluxCert.NewPool()
	signRoots.AddCert(caCert)
	encRoots := polluxCert.NewPool()
	encRoots.AddCert(caCert)

	cfg, err := polluxCert.BuildTLCPConfig(polluxCert.TLCPProxyOptions{
		Certificates: dual,
		SignRoots:    signRoots,
		EncRoots:     encRoots,
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("BuildTLCPConfig: %v", err)
	}

	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion: got %d, want %d", cfg.MinVersion, tls.VersionTLS12)
	}
}

func TestBlackBox_Cert_BuildTLCPConfig_RootCertificatesPreserved(t *testing.T) {
	dual, caCert, _ := generateTLCPDualCert(t, "sign.test", "enc.test")

	signRoots := polluxCert.NewPool()
	signRoots.AddCert(caCert)
	encRoots := polluxCert.NewPool()
	encRoots.AddCert(caCert)

	cfg, err := polluxCert.BuildTLCPConfig(polluxCert.TLCPProxyOptions{
		Certificates: dual,
		SignRoots:    signRoots,
		EncRoots:     encRoots,
	})
	if err != nil {
		t.Fatalf("BuildTLCPConfig: %v", err)
	}

	if len(cfg.SignRootCertificates) == 0 {
		t.Error("SignRootCertificates should be populated")
	}
	if len(cfg.EncRootCertificates) == 0 {
		t.Error("EncRootCertificates should be populated")
	}

	if len(cfg.SignRootCertificates) != 1 {
		t.Errorf("SignRootCertificates: got %d, want 1", len(cfg.SignRootCertificates))
	}
	if len(cfg.EncRootCertificates) != 1 {
		t.Errorf("EncRootCertificates: got %d, want 1", len(cfg.EncRootCertificates))
	}

	if cfg.SignRootCertificates[0].Subject.CommonName != "TLCP CA" {
		t.Errorf("SignRoot CA CN: got %q, want 'TLCP CA'", cfg.SignRootCertificates[0].Subject.CommonName)
	}
	if cfg.EncRootCertificates[0].Subject.CommonName != "TLCP CA" {
		t.Errorf("EncRoot CA CN: got %q, want 'TLCP CA'", cfg.EncRootCertificates[0].Subject.CommonName)
	}
}

func TestBlackBox_Cert_BuildTLCPConfig_SeparateRoots(t *testing.T) {
	dual, _, _ := generateTLCPDualCert(t, "sign.test", "enc.test")

	signCA, _, _ := generateSelfSignedCert(t, "sign-ca.test")
	encCA, _, _ := generateSelfSignedCert(t, "enc-ca.test")

	signRoots := polluxCert.NewPool()
	signRoots.AddCert(signCA)

	encRoots := polluxCert.NewPool()
	encRoots.AddCert(encCA)

	cfg, err := polluxCert.BuildTLCPConfig(polluxCert.TLCPProxyOptions{
		Certificates: dual,
		SignRoots:    signRoots,
		EncRoots:     encRoots,
	})
	if err != nil {
		t.Fatalf("BuildTLCPConfig: %v", err)
	}

	if len(cfg.SignRootCertificates) != 1 {
		t.Errorf("SignRootCertificates: got %d, want 1", len(cfg.SignRootCertificates))
	}
	if len(cfg.EncRootCertificates) != 1 {
		t.Errorf("EncRootCertificates: got %d, want 1", len(cfg.EncRootCertificates))
	}

	if cfg.SignRootCertificates[0].Subject.CommonName != "sign-ca.test" {
		t.Errorf("SignRoot CA CN: got %q", cfg.SignRootCertificates[0].Subject.CommonName)
	}
	if cfg.EncRootCertificates[0].Subject.CommonName != "enc-ca.test" {
		t.Errorf("EncRoot CA CN: got %q", cfg.EncRootCertificates[0].Subject.CommonName)
	}
}
