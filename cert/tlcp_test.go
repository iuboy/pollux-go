package cert

import (
	"crypto/tls"
	"encoding/pem"
	"strings"
	"testing"

	polluxTLCP "github.com/iuboy/pollux-go/tlcp"
)

// buildTestDual loads a throwaway sign/enc pair for TLCP config building.
func buildTestDual(t *testing.T) *DualCertificate {
	t.Helper()
	signCert, signKey := makeSM2KeyPairPEM(t, "tlcp-sign")
	encCert, encKey := makeSM2KeyPairPEM(t, "tlcp-enc")
	dual, err := LoadDualCertificatePEM(signCert, signKey, encCert, encKey)
	if err != nil {
		t.Fatalf("LoadDualCertificatePEM: %v", err)
	}
	return dual
}

func TestBuildTLCPConfig_Success(t *testing.T) {
	dual := buildTestDual(t)
	root := NewPoolFromCerts(mustParsePEM(t, dualPEM(t, dual)))

	cfg, err := BuildTLCPConfig(TLCPProxyOptions{
		Certificates: dual,
		SignRoots:    root,
		EncRoots:     root,
		ClientCAs:    root,
		ServerName:   "tlcp.test",
		ClientAuth:   polluxTLCP.RequireAndVerifyClientCert,
	})
	if err != nil {
		t.Fatalf("BuildTLCPConfig: %v", err)
	}
	if cfg.ServerName != "tlcp.test" {
		t.Fatalf("ServerName = %q", cfg.ServerName)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("default MinVersion = %x, want TLS1.2", cfg.MinVersion)
	}
	if len(cfg.CipherSuites) == 0 {
		t.Fatal("cipher suites should default to DefaultCipherSuites")
	}
	if cfg.SignCertificate == nil || cfg.EncCertificate == nil {
		t.Fatal("dual certificates not wired into config")
	}
	if cfg.SignRootCAs == nil || cfg.EncRootCAs == nil {
		t.Fatal("root pools not propagated")
	}
	if len(cfg.ClientCACertificates) == 0 {
		t.Fatal("client CA certs not propagated")
	}
}

func TestBuildTLCPConfig_Validation(t *testing.T) {
	if _, err := BuildTLCPConfig(TLCPProxyOptions{}); err == nil {
		t.Fatal("nil dual certificate should be rejected")
	}

	// Zero-value sign side (chain present but no key).
	dual := buildTestDual(t)
	brokenSign := *dual
	brokenSign.Sign.PrivateKey = nil
	if _, err := BuildTLCPConfig(TLCPProxyOptions{Certificates: &brokenSign}); err == nil ||
		!strings.Contains(err.Error(), "sign certificate") {
		t.Fatalf("broken sign side should fail with sign context, got: %v", err)
	}

	// Zero-value enc side (no chain at all).
	brokenEnc := *dual
	brokenEnc.Enc.Certificate = nil
	if _, err := BuildTLCPConfig(TLCPProxyOptions{Certificates: &brokenEnc}); err == nil ||
		!strings.Contains(err.Error(), "encrypt certificate") {
		t.Fatalf("broken enc side should fail with enc context, got: %v", err)
	}
}

// dualPEM re-encodes the sign leaf of a loaded dual pair for pool building.
func dualPEM(t *testing.T, dual *DualCertificate) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dual.Sign.Certificate[0]})
}
