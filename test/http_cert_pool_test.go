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
	polluxHttp "github.com/iuboy/pollux-go/http"
	polluxSM2 "github.com/iuboy/pollux-go/sm2"
	polluxSmx509 "github.com/iuboy/pollux-go/smx509"
)

// ========== Helper: 生成 SM2 CA 和叶子证书 ==========

func generateHTTPCACert(t *testing.T) (*x509.Certificate, *polluxSM2.PrivateKey, []byte) {
	t.Helper()

	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	ecPriv := ecdsa.PrivateKey{PublicKey: priv.PublicKey}
	ecPriv.D = priv.D

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "HTTP Test CA", Organization: []string{"HTTP Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := polluxSmx509.CreateCertificate(tmpl, tmpl, &ecPriv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	cert, err := polluxSmx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	return cert, priv, der
}

//lint:ignore U1000 retained for future HTTP server certificate chain tests
func generateHTTPServerCert(t *testing.T, caCert *x509.Certificate, caPriv *polluxSM2.PrivateKey, cn string) (*x509.Certificate, *polluxSM2.PrivateKey, tls.Certificate) {
	t.Helper()

	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
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
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"HTTP Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}

	der, err := polluxSmx509.CreateCertificate(tmpl, caCert, &ecPriv.PublicKey, &caECPriv)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	cert, err := polluxSmx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}

	return cert, priv, tlsCert
}

// ========== HTTP ServerOptions with cert.Pool ==========

func TestBlackBox_HTTP_ServerOptions_WithCertPool(t *testing.T) {
	caCert, _, caDER := generateHTTPCACert(t)
	serverPriv, _ := polluxSM2.GenerateKey(rand.Reader)
	serverCert := tls.Certificate{
		Certificate: [][]byte{caDER},
		PrivateKey:  serverPriv,
	}

	rootPool := polluxCert.NewPool()
	rootPool.AddCert(caCert)

	opts := &polluxHttp.ServerOptions{
		Addr:         ":443",
		Certificates: []tls.Certificate{serverCert},
		RootCAs:      rootPool,
	}

	if opts.RootCAs == nil {
		t.Error("RootCAs should be set")
	}
	if opts.RootCAs.Len() != 1 {
		t.Errorf("RootCAs length: got %d, want 1", opts.RootCAs.Len())
	}
}

func TestBlackBox_HTTP_ServerOptions_TLCPWithCertPools(t *testing.T) {
	signCA, _, signDER := generateHTTPCACert(t)
	encCA, _, encDER := generateHTTPCACert(t)

	signPriv, _ := polluxSM2.GenerateKey(rand.Reader)
	encPriv, _ := polluxSM2.GenerateKey(rand.Reader)

	signCert := tls.Certificate{
		Certificate: [][]byte{signDER},
		PrivateKey:  signPriv,
	}
	encCert := tls.Certificate{
		Certificate: [][]byte{encDER},
		PrivateKey:  encPriv,
	}

	signRoots := polluxCert.NewPool()
	signRoots.AddCert(signCA)

	encRoots := polluxCert.NewPool()
	encRoots.AddCert(encCA)

	opts := &polluxHttp.ServerOptions{
		Addr:        ":443",
		SignCert:    &signCert,
		EncCert:     &encCert,
		SignRootCAs: signRoots,
		EncRootCAs:  encRoots,
	}

	if opts.SignRootCAs == nil {
		t.Error("SignRootCAs should be set")
	}
	if opts.EncRootCAs == nil {
		t.Error("EncRootCAs should be set")
	}
}

func TestBlackBox_HTTP_ServerOptions_ClientAuthWithCertPool(t *testing.T) {
	caCert, _, caDER := generateHTTPCACert(t)
	serverPriv, _ := polluxSM2.GenerateKey(rand.Reader)
	serverCert := tls.Certificate{
		Certificate: [][]byte{caDER},
		PrivateKey:  serverPriv,
	}

	clientCA := polluxCert.NewPool()
	clientCA.AddCert(caCert)

	opts := &polluxHttp.ServerOptions{
		Addr:          ":443",
		Certificates:  []tls.Certificate{serverCert},
		ClientCAs:     clientCA,
		TLSClientAuth: tls.RequireAndVerifyClientCert,
	}

	if opts.ClientCAs == nil {
		t.Error("ClientCAs should be set")
	}
	if opts.ClientCAs.Len() != 1 {
		t.Errorf("ClientCAs length: got %d, want 1", opts.ClientCAs.Len())
	}
}

// ========== HTTP ClientOptions with cert.Pool ==========

func TestBlackBox_HTTP_ClientOptions_WithCertPool(t *testing.T) {
	caCert, _, _ := generateHTTPCACert(t)

	rootPool := polluxCert.NewPool()
	rootPool.AddCert(caCert)

	opts := &polluxHttp.ClientOptions{
		RootCAs: rootPool,
	}

	if opts.RootCAs == nil {
		t.Error("RootCAs should be set")
	}
	if opts.RootCAs.Len() != 1 {
		t.Errorf("RootCAs length: got %d, want 1", opts.RootCAs.Len())
	}
}

func TestBlackBox_HTTP_ClientOptions_TLCPWithCertPools(t *testing.T) {
	signCA, _, _ := generateHTTPCACert(t)
	encCA, _, _ := generateHTTPCACert(t)

	signRoots := polluxCert.NewPool()
	signRoots.AddCert(signCA)

	encRoots := polluxCert.NewPool()
	encRoots.AddCert(encCA)

	opts := &polluxHttp.ClientOptions{
		SignRootCAs: signRoots,
		EncRootCAs:  encRoots,
	}

	if opts.SignRootCAs == nil {
		t.Error("SignRootCAs should be set")
	}
	if opts.EncRootCAs == nil {
		t.Error("EncRootCAs should be set")
	}
}

// ========== Cert Pool Conversion Tests ==========

func TestBlackBox_HTTP_CertPoolToStandardConversion(t *testing.T) {
	caCert, _, _ := generateHTTPCACert(t)

	rootPool := polluxCert.NewPool()
	rootPool.AddCert(caCert)

	stdPool := rootPool.ToStandardPool()
	if stdPool == nil {
		t.Error("ToStandardPool should return non-nil pool")
	}

	rawDER := rootPool.RawDER()
	if len(rawDER) == 0 {
		t.Error("RawDER should not be empty")
	}

	certs := rootPool.Certificates()
	if len(certs) != 1 {
		t.Errorf("Certificates length: got %d, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "HTTP Test CA" {
		t.Errorf("CA CN: got %q, want 'HTTP Test CA'", certs[0].Subject.CommonName)
	}
}
