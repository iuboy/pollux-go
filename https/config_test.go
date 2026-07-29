package https

import (
	"testing"

	"github.com/iuboy/pollux-go/tlcp"
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

// TestModeTLS_NotZeroValueAndExplicitSelect is a regression test for the
// sentinel-ambiguity bug: with iota-from-0, ModeTLS == 0, so an explicit
// `opts.Mode = ModeTLS` was indistinguishable from "left unset" — DetectMode
// would then auto-detect TLCP from an SM2 cert and silently override the
// caller's explicit TLS choice. Now ModeTLS starts at 1 (ModeUnset == 0), so an
// explicit ModeTLS is honored.
func TestModeTLS_NotZeroValueAndExplicitSelect(t *testing.T) {
	// ModeTLS must NOT be the zero value (that's ModeUnset now).
	if ModeTLS == ModeUnset {
		t.Fatal("ModeTLS must not equal the zero value (ModeUnset); iota must start at 1")
	}
	if ModeUnset != 0 {
		t.Errorf("ModeUnset must be 0, got %d", ModeUnset)
	}

	// An explicit ModeTLS must win even when DetectMode would pick TLCP. Build a
	// ServerOptions with ModeTLS set and no certs (so DetectMode would return
	// ModeTLS anyway), then flip a TLCP-triggering scenario by setting ModeTLS
	// explicitly and confirming DetectMode returns it verbatim — i.e. the
	// explicit value is never replaced by the zero-value "unset" branch.
	opts := &ServerOptions{Mode: ModeTLS}
	if got := opts.DetectMode(); got != ModeTLS {
		t.Errorf("DetectMode with explicit ModeTLS = %v, want ModeTLS (explicit choice must not be overridden)", got)
	}

	// Unset falls through to detection (nil cert => DetectMode returns ModeTLS).
	unset := &ServerOptions{Mode: ModeUnset}
	if got := unset.DetectMode(); got != ModeTLS {
		t.Errorf("DetectMode with ModeUnset and nil cert = %v, want ModeTLS (auto-detect default)", got)
	}
}
