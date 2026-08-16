package cert

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	polluxSM2 "github.com/iuboy/pollux-go/sm2"
	polluxSmx509 "github.com/iuboy/pollux-go/smx509"
)

// makeSM2KeyPairPEM generates a self-signed SM2 certificate and returns its
// PEM-encoded form alongside the matching private-key PEM.
func makeSM2KeyPairPEM(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	ecPriv, err := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	sm2Priv := new(polluxSM2.PrivateKey)
	if _, err := sm2Priv.FromECPrivateKey(ecPriv); err != nil {
		t.Fatalf("convert SM2 key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := polluxSmx509.CreateCertificate(tmpl, tmpl, &ecPriv.PublicKey, sm2Priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	key, err := polluxSM2.WritePrivateKeyToPEM(sm2Priv)
	if err != nil {
		t.Fatalf("WritePrivateKeyToPEM: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key
}

func TestLoadKeyPairPEM_RoundTrip(t *testing.T) {
	certPEM, keyPEM := makeSM2KeyPairPEM(t, "load-roundtrip")
	pair, err := LoadKeyPairPEM(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadKeyPairPEM: %v", err)
	}
	if len(pair.Certificate) != 1 {
		t.Fatalf("chain length = %d, want 1", len(pair.Certificate))
	}
	if pair.PrivateKey == nil {
		t.Fatal("private key is nil")
	}
}

func TestLoadKeyPairPEM_ChainCollected(t *testing.T) {
	// Two CERTIFICATE blocks (leaf + a second block) must both be collected
	// so the full chain is presented during the handshake.
	leafPEM, keyPEM := makeSM2KeyPairPEM(t, "leaf")
	otherPEM, _ := makeSM2KeyPairPEM(t, "chain-extra")
	combined := append(append([]byte{}, leafPEM...), otherPEM...)

	pair, err := LoadKeyPairPEM(combined, keyPEM)
	if err != nil {
		t.Fatalf("LoadKeyPairPEM with chain: %v", err)
	}
	if len(pair.Certificate) != 2 {
		t.Fatalf("chain length = %d, want 2", len(pair.Certificate))
	}
}

func TestLoadKeyPairPEM_KeyMismatch(t *testing.T) {
	certPEM, _ := makeSM2KeyPairPEM(t, "cert-a")
	_, otherKeyPEM := makeSM2KeyPairPEM(t, "key-b")

	_, err := LoadKeyPairPEM(certPEM, otherKeyPEM)
	if err == nil {
		t.Fatal("mismatched key should be rejected")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error should mention the mismatch, got: %v", err)
	}
}

func TestLoadKeyPairPEM_BadInputs(t *testing.T) {
	certPEM, keyPEM := makeSM2KeyPairPEM(t, "bad-inputs")

	cases := []struct {
		name    string
		certIn  []byte
		keyIn   []byte
		wantErr string
	}{
		{"no PEM at all", []byte("not a pem"), keyPEM, "failed to decode"},
		{"wrong block type", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), keyPEM, "no CERTIFICATE-typed block"},
		{"garbage key", certPEM, []byte("-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n"), "parse private key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadKeyPairPEM(tc.certIn, tc.keyIn)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) && tc.wantErr != "failed to decode" {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadKeyPairFiles_RoundTripAndMissingFile(t *testing.T) {
	certPEM, keyPEM := makeSM2KeyPairPEM(t, "files-roundtrip")
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.pem")
	keyPath := filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	pair, err := LoadKeyPairFiles(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadKeyPairFiles: %v", err)
	}
	if len(pair.Certificate) != 1 || pair.PrivateKey == nil {
		t.Fatal("incomplete pair")
	}

	if _, err := LoadKeyPairFiles(filepath.Join(dir, "missing.pem"), keyPath); err == nil {
		t.Fatal("missing cert file should error")
	}
}

func TestLoadDualCertificatePEM(t *testing.T) {
	signCert, signKey := makeSM2KeyPairPEM(t, "dual-sign")
	encCert, encKey := makeSM2KeyPairPEM(t, "dual-enc")

	dual, err := LoadDualCertificatePEM(signCert, signKey, encCert, encKey)
	if err != nil {
		t.Fatalf("LoadDualCertificatePEM: %v", err)
	}
	if dual.Sign.PrivateKey == nil || dual.Enc.PrivateKey == nil {
		t.Fatal("both sides must carry a private key")
	}

	// A mismatched ENC key must surface with the "load enc cert" context so
	// the operator knows which side of the pair failed.
	_, otherKey := makeSM2KeyPairPEM(t, "dual-other")
	_, err = LoadDualCertificatePEM(signCert, signKey, encCert, otherKey)
	if err == nil || !strings.Contains(err.Error(), "load enc cert") {
		t.Fatalf("enc-side failure should carry 'load enc cert' context, got: %v", err)
	}
}

func TestLoadDualCertificateFiles(t *testing.T) {
	signCert, signKey := makeSM2KeyPairPEM(t, "dual-files-sign")
	encCert, encKey := makeSM2KeyPairPEM(t, "dual-files-enc")
	dir := t.TempDir()
	paths := map[string][]byte{
		"sign.crt": signCert, "sign.key": signKey,
		"enc.crt": encCert, "enc.key": encKey,
	}
	for name, data := range paths {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	dual, err := LoadDualCertificateFiles(
		filepath.Join(dir, "sign.crt"), filepath.Join(dir, "sign.key"),
		filepath.Join(dir, "enc.crt"), filepath.Join(dir, "enc.key"))
	if err != nil {
		t.Fatalf("LoadDualCertificateFiles: %v", err)
	}
	if dual.Sign.PrivateKey == nil || dual.Enc.PrivateKey == nil {
		t.Fatal("incomplete dual pair")
	}

	if _, err := LoadDualCertificateFiles(
		filepath.Join(dir, "sign.crt"), filepath.Join(dir, "sign.key"),
		filepath.Join(dir, "enc.crt"), filepath.Join(dir, "nope.key")); err == nil {
		t.Fatal("missing enc key should error")
	}
}

func TestParseCertificateRequest_Delegates(t *testing.T) {
	key, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := polluxSmx509.CreateCertificateRequest(&x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "csr-cn"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if csr.Subject.CommonName != "csr-cn" {
		t.Fatalf("CN = %q", csr.Subject.CommonName)
	}
	if _, err := ParseCertificateRequest([]byte{0x30, 0x00}); err == nil {
		t.Fatal("malformed CSR should error")
	}
}

// --- tls.go ---

func TestBuildClientTLSConfig(t *testing.T) {
	if _, err := BuildClientTLSConfig(TLSClientOptions{}); err == nil {
		t.Fatal("empty client options should be rejected")
	}

	// InsecureSkipVerify alone is a valid (test) configuration.
	cfg, err := BuildClientTLSConfig(TLSClientOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("InsecureSkipVerify-only build: %v", err)
	}
	if !cfg.InsecureSkipVerify || cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("defaults wrong: insecure=%v minVer=%x", cfg.InsecureSkipVerify, cfg.MinVersion)
	}

	certPEM, keyPEM := makeSM2KeyPairPEM(t, "tls-client")
	pair, err := LoadKeyPairPEM(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	root := NewPoolFromCerts(mustParsePEM(t, certPEM))
	cfg, err = BuildClientTLSConfig(TLSClientOptions{
		ServerName:   "example.com",
		Roots:        root,
		Certificates: []tls.Certificate{pair},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("full build: %v", err)
	}
	if cfg.ServerName != "example.com" || cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("fields not propagated: %v %x", cfg.ServerName, cfg.MinVersion)
	}
	if cfg.RootCAs == nil || len(cfg.Certificates) != 1 {
		t.Fatal("roots/certificates not propagated")
	}
}

func TestBuildServerTLSConfig(t *testing.T) {
	if _, err := BuildServerTLSConfig(TLSProxyServerOptions{}); err == nil {
		t.Fatal("server build without certificates should fail")
	}

	certPEM, keyPEM := makeSM2KeyPairPEM(t, "tls-server")
	pair, err := LoadKeyPairPEM(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	clientCAPool := NewPoolFromCerts(mustParsePEM(t, certPEM))

	cfg, err := BuildServerTLSConfig(TLSProxyServerOptions{
		Certificates: []tls.Certificate{pair},
		ClientCAs:    clientCAPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("default MinVersion = %x, want TLS1.2", cfg.MinVersion)
	}
	if cfg.ClientCAs == nil || cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatal("client CA settings not propagated")
	}
}

func mustParsePEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	return cert
}
