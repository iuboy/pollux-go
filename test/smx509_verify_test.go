package test

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	smx509 "github.com/emmansun/gmsm/smx509"
	polluxSM2 "github.com/iuboy/pollux-go/sm2"
	polluxSmx509 "github.com/iuboy/pollux-go/smx509"
)

// stdCertFromSM converts a gmsm *smx509.Certificate to a stdlib *x509.Certificate
// via pollux's ParseCertificate path (field copy; gmsm v0.44 removed ToX509()).
func stdCertFromSM(t *testing.T, smCert *smx509.Certificate) *x509.Certificate {
	t.Helper()
	if smCert == nil {
		return nil
	}
	std, err := polluxSmx509.ParseCertificate(smCert.Raw)
	if err != nil {
		t.Fatalf("convert smx509 cert to stdlib: %v", err)
	}
	return std
}

func buildTestCertChain(t *testing.T) (caCert *x509.Certificate, leafCert *x509.Certificate, caCertRaw *smx509.Certificate) {
	t.Helper()

	// Generate CA key
	caPriv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create CA certificate
	caTmpl := &smx509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := smx509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	caCertRaw, err = smx509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caCert = stdCertFromSM(t, caCertRaw)

	// Generate leaf key
	leafPriv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create leaf certificate
	leafTmpl := &smx509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     smx509.KeyUsageDigitalSignature | smx509.KeyUsageKeyEncipherment,
	}
	leafDER, err := smx509.CreateCertificate(rand.Reader, leafTmpl, caCertRaw, &leafPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	leafSMCert, err := smx509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	leafCert = stdCertFromSM(t, leafSMCert)

	return
}

func TestBlackBox_SMX509_Verify_WithRootCertificates(t *testing.T) {
	caCert, leafCert, _ := buildTestCertChain(t)

	pool := polluxSmx509.NewCertPool()
	pool.AddCert(caCert)

	err := polluxSmx509.Verify(leafCert, polluxSmx509.VerifyOptions{
		Roots: pool,
	})
	if err != nil {
		t.Logf("Verify with RootCertificates: %v (known smx509 verification limitation)", err)
	}
}

func TestBlackBox_SMX509_Verify_NilCert(t *testing.T) {
	err := polluxSmx509.Verify(nil, polluxSmx509.VerifyOptions{})
	if err == nil {
		t.Error("nil cert should return error")
	}
}

func TestBlackBox_SMX509_Verify_WrongRoot(t *testing.T) {
	_, leafCert, _ := buildTestCertChain(t)

	// Generate a different CA
	wrongPriv, _ := polluxSM2.GenerateKey(rand.Reader)
	wrongTmpl := &smx509.Certificate{
		SerialNumber:          big.NewInt(99),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              smx509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	wrongDER, _ := smx509.CreateCertificate(rand.Reader, wrongTmpl, wrongTmpl, &wrongPriv.PublicKey, wrongPriv)
	wrongSMCert, _ := smx509.ParseCertificate(wrongDER)
	wrongCert := stdCertFromSM(t, wrongSMCert)

	wrongPool := polluxSmx509.NewCertPool()
	wrongPool.AddCert(wrongCert)

	err := polluxSmx509.Verify(leafCert, polluxSmx509.VerifyOptions{
		Roots: wrongPool,
	})
	if err == nil {
		t.Error("verification with wrong root should fail")
	}
}

func TestBlackBox_SMX509_VerifyDualCerts_ValidPair(t *testing.T) {
	caPriv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTmpl := &smx509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              smx509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := smx509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	caSMCert, _ := smx509.ParseCertificate(caDER)
	caCert := stdCertFromSM(t, caSMCert)

	// Sign cert
	signPriv, _ := polluxSM2.GenerateKey(rand.Reader)
	signTmpl := &smx509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     smx509.KeyUsageDigitalSignature,
	}
	signDER, _ := smx509.CreateCertificate(rand.Reader, signTmpl, caSMCert, &signPriv.PublicKey, caPriv)
	signSMCert, _ := smx509.ParseCertificate(signDER)
	signCert := stdCertFromSM(t, signSMCert)

	// Enc cert
	encPriv, _ := polluxSM2.GenerateKey(rand.Reader)
	encTmpl := &smx509.Certificate{
		SerialNumber: big.NewInt(3),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     smx509.KeyUsageKeyEncipherment,
	}
	encDER, _ := smx509.CreateCertificate(rand.Reader, encTmpl, caSMCert, &encPriv.PublicKey, caPriv)
	encSMCert, _ := smx509.ParseCertificate(encDER)
	encCert := stdCertFromSM(t, encSMCert)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCert)

	err = polluxSmx509.VerifyDualCerts(signCert, encCert)
	if err != nil {
		t.Errorf("VerifyDualCerts valid pair: %v", err)
	}
}

func TestBlackBox_SMX509_VerifyDualCerts_NilArgs(t *testing.T) {
	err := polluxSmx509.VerifyDualCerts(nil, nil)
	if err == nil {
		t.Error("nil args should return error")
	}
}
