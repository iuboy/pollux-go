package http

import (
	"testing"

	"github.com/ycq/pollux/tlcp"
)

func TestLoadTLCPCertificates(t *testing.T) {
	// This would require actual certificate files
	// For now, just test that invalid paths fail
	opts := &ServerOptions{}

	err := opts.LoadTLCPCertificates(
		"/nonexistent/sign_cert.pem",
		"/nonexistent/sign_key.pem",
		"/nonexistent/enc_cert.pem",
		"/nonexistent/enc_key.pem",
	)
	if err == nil {
		t.Error("nonexistent files should error")
	}
}

func TestLoadTLSCertificate(t *testing.T) {
	opts := &ServerOptions{}

	err := opts.LoadTLSCertificate(
		"/nonexistent/cert.pem",
		"/nonexistent/key.pem",
	)
	if err == nil {
		t.Error("nonexistent files should error")
	}
}

func TestLoadSM2KeyPairFromFile(t *testing.T) {
	_, err := loadSM2KeyPairFromFile("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Error("nonexistent files should error")
	}
}

func TestTLCPDefaultCipherSuites(t *testing.T) {
	suites := tlcp.DefaultCipherSuites()
	if len(suites) == 0 {
		t.Error("cipher suites should not be empty")
	}
}
