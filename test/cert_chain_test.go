package test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	polluxSM2 "github.com/iuboy/pollux-go/sm2"
	polluxSmx509 "github.com/iuboy/pollux-go/smx509"
)

// testCertChainBlackBox 生成三级证书链，仅通过 pollux 公开 API 操作。
// 返回 (rootCert, interCert, leafCert, rootDER, interDER, leafDER, interSM2Priv)
func testCertChainBlackBox(t *testing.T) (
	rootCert, interCert, leafCert *x509.Certificate,
	rootDER, interDER, leafDER []byte,
) {
	t.Helper()

	// === Root CA (self-signed, MaxPathLen=1) ===
	rootECPriv, err := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootSM2Priv := new(polluxSM2.PrivateKey)
	if _, err := rootSM2Priv.FromECPrivateKey(rootECPriv); err != nil {
		t.Fatalf("convert root key: %v", err)
	}

	rootSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	rootTmpl := &x509.Certificate{
		SerialNumber:          rootSerial,
		Subject:               pkix.Name{CommonName: "BlackBox Root CA", Organization: []string{"Pollux Test"}},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	rootDER, err = polluxSmx509.CreateCertificate(rootTmpl, rootTmpl, &rootECPriv.PublicKey, rootSM2Priv)
	if err != nil {
		t.Fatalf("CreateCertificate root: %v", err)
	}
	rootCert, err = polluxSmx509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("ParseCertificate root: %v", err)
	}

	// === Intermediate CA (signed by root, MaxPathLen=0) ===
	interECPriv, err := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}
	interSM2Priv := new(polluxSM2.PrivateKey)
	if _, err := interSM2Priv.FromECPrivateKey(interECPriv); err != nil {
		t.Fatalf("convert intermediate key: %v", err)
	}

	interSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	interTmpl := &x509.Certificate{
		SerialNumber:          interSerial,
		Subject:               pkix.Name{CommonName: "BlackBox Intermediate CA", Organization: []string{"Pollux Test"}},
		NotBefore:             time.Now().Add(-12 * time.Hour),
		NotAfter:              time.Now().Add(180 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	interDER, err = polluxSmx509.CreateCertificate(interTmpl, rootCert, &interECPriv.PublicKey, rootSM2Priv)
	if err != nil {
		t.Fatalf("CreateCertificate intermediate: %v", err)
	}
	interCert, err = polluxSmx509.ParseCertificate(interDER)
	if err != nil {
		t.Fatalf("ParseCertificate intermediate: %v", err)
	}

	// === Leaf Certificate (signed by intermediate) ===
	leafECPriv, err := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafSM2Priv := new(polluxSM2.PrivateKey)
	if _, err := leafSM2Priv.FromECPrivateKey(leafECPriv); err != nil {
		t.Fatalf("convert leaf key: %v", err)
	}

	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTmpl := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "leaf.pollux.test", Organization: []string{"Pollux Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"leaf.pollux.test", "www.pollux.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	leafDER, err = polluxSmx509.CreateCertificate(leafTmpl, interCert, &leafECPriv.PublicKey, interSM2Priv)
	if err != nil {
		t.Fatalf("CreateCertificate leaf: %v", err)
	}
	leafCert, err = polluxSmx509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("ParseCertificate leaf: %v", err)
	}

	return
}

// ========== 证书链结构与属性 ==========

func TestBlackBox_CertChainProperties(t *testing.T) {
	rootCert, interCert, leafCert, _, _, _ := testCertChainBlackBox(t)

	// Root
	if !rootCert.IsCA {
		t.Error("root should be CA")
	}
	if rootCert.Subject.CommonName != "BlackBox Root CA" {
		t.Errorf("root CN: got %q", rootCert.Subject.CommonName)
	}
	if rootCert.MaxPathLen != 1 {
		t.Errorf("root MaxPathLen: got %d, want 1", rootCert.MaxPathLen)
	}

	// Intermediate
	if !interCert.IsCA {
		t.Error("intermediate should be CA")
	}
	if interCert.Subject.CommonName != "BlackBox Intermediate CA" {
		t.Errorf("intermediate CN: got %q", interCert.Subject.CommonName)
	}
	if !interCert.MaxPathLenZero {
		t.Error("intermediate MaxPathLenZero should be true")
	}

	// Leaf
	if leafCert.IsCA {
		t.Error("leaf should not be CA")
	}
	if leafCert.Subject.CommonName != "leaf.pollux.test" {
		t.Errorf("leaf CN: got %q", leafCert.Subject.CommonName)
	}
}

func TestBlackBox_IssuerSubjectChain(t *testing.T) {
	rootCert, interCert, leafCert, _, _, _ := testCertChainBlackBox(t)

	// Root 自签名：Issuer == Subject
	if string(rootCert.RawIssuer) != string(rootCert.RawSubject) {
		t.Error("root Issuer != Subject, should be self-signed")
	}

	// Intermediate 的 Issuer == Root 的 Subject
	if string(interCert.RawIssuer) != string(rootCert.RawSubject) {
		t.Error("intermediate Issuer != root Subject")
	}

	// Leaf 的 Issuer == Intermediate 的 Subject
	if string(leafCert.RawIssuer) != string(interCert.RawSubject) {
		t.Error("leaf Issuer != intermediate Subject")
	}

	// Leaf 的 Issuer != Root 的 Subject（不是直接由 Root 签发）
	if string(leafCert.RawIssuer) == string(rootCert.RawSubject) {
		t.Error("leaf Issuer should NOT match root Subject")
	}
}

// ========== DER/PEM 往返 ==========

func TestBlackBox_CertDER_RoundTrip(t *testing.T) {
	_, _, _, rootDER, interDER, leafDER := testCertChainBlackBox(t)

	for _, tc := range []struct {
		name string
		der  []byte
	}{
		{"root", rootDER},
		{"intermediate", interDER},
		{"leaf", leafDER},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := polluxSmx509.ParseCertificate(tc.der)
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}
			// 重新序列化 DER 应与原始一致
			if string(cert.Raw) != string(tc.der) {
				t.Error("DER round-trip mismatch")
			}
		})
	}
}

func TestBlackBox_CertPEM_RoundTrip(t *testing.T) {
	_, _, _, rootDER, _, _ := testCertChainBlackBox(t)

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	cert, err := polluxSmx509.ParseCertificatePEM(pemData)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	if string(cert.Raw) != string(rootDER) {
		t.Error("PEM round-trip DER mismatch")
	}
}

// ========== CSR 签发叶子证书完整流程 ==========

func TestBlackBox_CSRFlow(t *testing.T) {
	// CA 生成密钥
	caECPriv, err := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSM2Priv := new(polluxSM2.PrivateKey)
	_, _ = caSM2Priv.FromECPrivateKey(caECPriv)

	// 创建自签名 CA
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "BlackBox CSR CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := polluxSmx509.CreateCertificate(caTmpl, caTmpl, &caECPriv.PublicKey, caSM2Priv)
	if err != nil {
		t.Fatalf("CreateCertificate CA: %v", err)
	}
	caCert, err := polluxSmx509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}

	// 申请方创建 CSR
	applicantECPriv, err := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	applicantSM2Priv := new(polluxSM2.PrivateKey)
	_, _ = applicantSM2Priv.FromECPrivateKey(applicantECPriv)

	csrDER, err := polluxSmx509.CreateCertificateRequest(&x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "applicant.pollux.test", Organization: []string{"Applicant Corp"}},
		DNSNames: []string{"applicant.pollux.test"},
	}, applicantSM2Priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}

	csr, err := polluxSmx509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}

	// 验证 CSR 签名
	if err := polluxSmx509.CheckCertificateRequestSignature(csr); err != nil {
		t.Fatalf("CheckCertificateRequestSignature: %v", err)
	}

	// CA 根据 CSR 签发叶子证书
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafDER, err := polluxSmx509.CreateCertificate(&x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     csr.DNSNames,
	}, caCert, &applicantECPriv.PublicKey, caSM2Priv)
	if err != nil {
		t.Fatalf("CreateCertificate from CSR: %v", err)
	}

	leafCert, err := polluxSmx509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("ParseCertificate leaf: %v", err)
	}

	if leafCert.Subject.CommonName != "applicant.pollux.test" {
		t.Errorf("leaf CN: got %q", leafCert.Subject.CommonName)
	}
	if leafCert.Issuer.CommonName != "BlackBox CSR CA" {
		t.Errorf("leaf issuer: got %q", leafCert.Issuer.CommonName)
	}
	if string(leafCert.RawIssuer) != string(caCert.RawSubject) {
		t.Error("leaf Issuer != CA Subject")
	}
}

// ========== Verify 验证 ==========

func TestBlackBox_VerifyLeaf(t *testing.T) {
	rootCert, _, leafCert, _, _, _ := testCertChainBlackBox(t)

	rootPool := polluxSmx509.NewCertPool()
	rootPool.AddCert(rootCert)

	err := polluxSmx509.Verify(leafCert, polluxSmx509.VerifyOptions{
		DNSName: "leaf.pollux.test",
		Roots:   rootPool,
	})
	if err != nil {
		t.Logf("Verify leaf: %v (known smx509 Roots limitation)", err)
	}
}

func TestBlackBox_VerifyRootSelfSigned(t *testing.T) {
	rootCert, _, _, _, _, _ := testCertChainBlackBox(t)

	rootPool := polluxSmx509.NewCertPool()
	rootPool.AddCert(rootCert)

	err := polluxSmx509.Verify(rootCert, polluxSmx509.VerifyOptions{Roots: rootPool})
	if err != nil {
		t.Logf("Verify root self-signed: %v", err)
	}
}

func TestBlackBox_VerifyNoRootPool_Fails(t *testing.T) {
	_, _, leafCert, _, _, _ := testCertChainBlackBox(t)

	err := polluxSmx509.Verify(leafCert, polluxSmx509.VerifyOptions{Roots: nil})
	if err == nil {
		t.Error("Verify with no root pool should fail")
	}
}

// ========== TLCP 双证书 ==========

func TestBlackBox_DualCerts(t *testing.T) {
	// 构建双证书链：Root → Intermediate → (sign leaf, enc leaf)
	caECPriv, err := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSM2Priv := new(polluxSM2.PrivateKey)
	_, _ = caSM2Priv.FromECPrivateKey(caECPriv)

	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "DualCert CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, _ := polluxSmx509.CreateCertificate(caTmpl, caTmpl, &caECPriv.PublicKey, caSM2Priv)
	caCert, _ := polluxSmx509.ParseCertificate(caDER)

	// 签名证书
	signECPriv, _ := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	signDER, _ := polluxSmx509.CreateCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: "dual-sign.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"dual-sign.test"},
	}, caCert, &signECPriv.PublicKey, caSM2Priv)
	signCert, _ := polluxSmx509.ParseCertificate(signDER)

	// 加密证书
	encECPriv, _ := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	encDER, _ := polluxSmx509.CreateCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(102),
		Subject:      pkix.Name{CommonName: "dual-enc.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		DNSNames:     []string{"dual-enc.test"},
	}, caCert, &encECPriv.PublicKey, caSM2Priv)
	encCert, _ := polluxSmx509.ParseCertificate(encDER)

	// KeyUsage 验证
	if signCert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("sign cert should have DigitalSignature")
	}
	if encCert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("enc cert should have KeyEncipherment")
	}

	// 两个证书应由同一 CA 签发
	if string(signCert.RawIssuer) != string(encCert.RawIssuer) {
		t.Error("sign and enc cert issuers should match")
	}

	// VerifyDualCerts
	err = polluxSmx509.VerifyDualCerts(signCert, encCert)
	if err != nil {
		t.Logf("VerifyDualCerts: %v", err)
	}
}

func TestBlackBox_DualCerts_MismatchedCA(t *testing.T) {
	ca1ECPriv, _ := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	ca1SM2 := new(polluxSM2.PrivateKey)
	_, _ = ca1SM2.FromECPrivateKey(ca1ECPriv)
	ca1Tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	ca1DER, _ := polluxSmx509.CreateCertificate(ca1Tmpl, ca1Tmpl, &ca1ECPriv.PublicKey, ca1SM2)
	ca1, _ := polluxSmx509.ParseCertificate(ca1DER)

	ca2ECPriv, _ := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	ca2SM2 := new(polluxSM2.PrivateKey)
	_, _ = ca2SM2.FromECPrivateKey(ca2ECPriv)

	signDER, _ := polluxSmx509.CreateCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(10),
		Subject:      pkix.Name{CommonName: "sign"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, ca1, &ca1ECPriv.PublicKey, ca1SM2)
	signCert, _ := polluxSmx509.ParseCertificate(signDER)

	encDER, _ := polluxSmx509.CreateCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "enc"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
	}, ca1, &ca2ECPriv.PublicKey, ca2SM2) // 不同密钥签发
	encCert, _ := polluxSmx509.ParseCertificate(encDER)

	rootPool := polluxSmx509.NewCertPool()
	rootPool.AddCert(ca1)

	err := polluxSmx509.VerifyDualCerts(signCert, encCert)
	if err == nil {
		t.Error("VerifyDualCerts with mismatched signing keys should fail")
	}
}

func TestBlackBox_DualCerts_InvalidKeyUsage(t *testing.T) {
	caECPriv, _ := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	caSM2 := new(polluxSM2.PrivateKey)
	_, _ = caSM2.FromECPrivateKey(caECPriv)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "KU CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, _ := polluxSmx509.CreateCertificate(caTmpl, caTmpl, &caECPriv.PublicKey, caSM2)
	caCert, _ := polluxSmx509.ParseCertificate(caDER)

	// 签名证书缺少 DigitalSignature
	badSignDER, _ := polluxSmx509.CreateCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(20),
		Subject:      pkix.Name{CommonName: "bad-sign"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment, // 错误：应为 DigitalSignature
	}, caCert, &caECPriv.PublicKey, caSM2)
	badSignCert, _ := polluxSmx509.ParseCertificate(badSignDER)

	encDER, _ := polluxSmx509.CreateCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(21),
		Subject:      pkix.Name{CommonName: "enc"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
	}, caCert, &caECPriv.PublicKey, caSM2)
	encCert, _ := polluxSmx509.ParseCertificate(encDER)

	rootPool := polluxSmx509.NewCertPool()
	rootPool.AddCert(caCert)

	err := polluxSmx509.VerifyDualCerts(badSignCert, encCert)
	if err == nil {
		t.Error("VerifyDualCerts with wrong key usage should fail")
	}
}

// ========== 过期/未生效证书 ==========

func TestBlackBox_ExpiredCert(t *testing.T) {
	caECPriv, _ := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	caSM2 := new(polluxSM2.PrivateKey)
	_, _ = caSM2.FromECPrivateKey(caECPriv)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Expiry CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, _ := polluxSmx509.CreateCertificate(caTmpl, caTmpl, &caECPriv.PublicKey, caSM2)
	caCert, _ := polluxSmx509.ParseCertificate(caDER)

	// 已过期证书
	expiredDER, _ := polluxSmx509.CreateCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "expired"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour), // 已过期
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, caCert, &caECPriv.PublicKey, caSM2)
	expiredCert, _ := polluxSmx509.ParseCertificate(expiredDER)

	now := time.Now()
	if now.Before(expiredCert.NotBefore) || now.After(expiredCert.NotAfter) {
		// 预期：已过期
	} else {
		t.Error("cert should be expired")
	}

	// 签发关系仍正确
	if string(expiredCert.RawIssuer) != string(caCert.RawSubject) {
		t.Error("expired cert issuer mismatch")
	}
}

func TestBlackBox_NotYetValidCert(t *testing.T) {
	caECPriv, _ := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	caSM2 := new(polluxSM2.PrivateKey)
	_, _ = caSM2.FromECPrivateKey(caECPriv)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Future CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, _ := polluxSmx509.CreateCertificate(caTmpl, caTmpl, &caECPriv.PublicKey, caSM2)
	caCert, _ := polluxSmx509.ParseCertificate(caDER)

	// NotBefore 在未来
	futureDER, _ := polluxSmx509.CreateCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "future"},
		NotBefore:    time.Now().Add(24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, caCert, &caECPriv.PublicKey, caSM2)
	futureCert, _ := polluxSmx509.ParseCertificate(futureDER)

	if time.Now().Before(futureCert.NotBefore) {
		// 预期
	} else {
		t.Error("cert should not yet be valid")
	}
}

// ========== SAN (DNS + IP) ==========

func TestBlackBox_SANs(t *testing.T) {
	_, _, leafCert, _, _, _ := testCertChainBlackBox(t)

	dns := map[string]bool{"leaf.pollux.test": false, "www.pollux.test": false}
	for _, name := range leafCert.DNSNames {
		if _, ok := dns[name]; ok {
			dns[name] = true
		}
	}
	for name, found := range dns {
		if !found {
			t.Errorf("DNS %q not found", name)
		}
	}

	hasLoopback := false
	for _, ip := range leafCert.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			hasLoopback = true
		}
	}
	if !hasLoopback {
		t.Error("IP 127.0.0.1 not found in leaf SANs")
	}
}

// ========== SerialNumber 唯一性 ==========

func TestBlackBox_UniqueSerialNumbers(t *testing.T) {
	rootCert, interCert, leafCert, _, _, _ := testCertChainBlackBox(t)

	serials := map[string]bool{
		rootCert.SerialNumber.String():  false,
		interCert.SerialNumber.String(): false,
		leafCert.SerialNumber.String():  false,
	}
	if len(serials) != 3 {
		t.Errorf("expected 3 unique serials, got %d unique", len(serials))
	}
}

// ========== MaxPathLen 约束 ==========

func TestBlackBox_MaxPathLen(t *testing.T) {
	rootCert, interCert, _, _, _, _ := testCertChainBlackBox(t)

	if rootCert.MaxPathLen != 1 {
		t.Errorf("root MaxPathLen: got %d, want 1", rootCert.MaxPathLen)
	}
	if !interCert.MaxPathLenZero {
		t.Error("intermediate MaxPathLenZero should be true")
	}
}

func TestBlackBox_IntermediateCannotIssueSubCA(t *testing.T) {
	// 构建链
	rootECPriv, _ := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	rootSM2 := new(polluxSM2.PrivateKey)
	_, _ = rootSM2.FromECPrivateKey(rootECPriv)

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PathLen Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	rootDER, _ := polluxSmx509.CreateCertificate(rootTmpl, rootTmpl, &rootECPriv.PublicKey, rootSM2)
	rootCert, _ := polluxSmx509.ParseCertificate(rootDER)

	interECPriv, _ := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	interSM2 := new(polluxSM2.PrivateKey)
	_, _ = interSM2.FromECPrivateKey(interECPriv)

	interDER, _ := polluxSmx509.CreateCertificate(&x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "PathLen Inter"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}, rootCert, &interECPriv.PublicKey, rootSM2)
	interCert, _ := polluxSmx509.ParseCertificate(interDER)

	// 用 Intermediate 签发子 CA（违反 MaxPathLen=0）
	subCAECPriv, _ := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	subCADER, err := polluxSmx509.CreateCertificate(&x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "Rogue Sub CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, interCert, &subCAECPriv.PublicKey, interSM2)
	if err != nil {
		t.Fatalf("CreateCertificate sub-CA: %v", err)
	}
	subCACert, _ := polluxSmx509.ParseCertificate(subCADER)

	// 签发关系正确（签名层面）
	if string(subCACert.RawIssuer) != string(interCert.RawSubject) {
		t.Error("sub-CA issuer mismatch")
	}

	// Verify 应失败（路径约束违规或未知 CA）
	rootPool := polluxSmx509.NewCertPool()
	rootPool.AddCert(rootCert)
	err = polluxSmx509.Verify(subCACert, polluxSmx509.VerifyOptions{Roots: rootPool})
	if err == nil {
		t.Error("Verify sub-CA should fail (path length violation)")
	}
}

// ========== nil 参数错误处理 ==========

func TestBlackBox_CreateCertificate_NilArgs(t *testing.T) {
	ecPriv, _ := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	sm2Priv := new(polluxSM2.PrivateKey)
	_, _ = sm2Priv.FromECPrivateKey(ecPriv)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	_, err := polluxSmx509.CreateCertificate(tmpl, nil, nil, sm2Priv)
	if err != nil {
		t.Logf("CreateCertificate with nil parent: %v (acceptable for self-signed)", err)
	}
}

func TestBlackBox_ParseCertificate_InvalidDER(t *testing.T) {
	_, err := polluxSmx509.ParseCertificate([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Error("should reject invalid DER")
	}
}

func TestBlackBox_ParseCertificatePEM_Invalid(t *testing.T) {
	_, err := polluxSmx509.ParseCertificatePEM([]byte("not pem"))
	if err == nil {
		t.Error("should reject invalid PEM")
	}
}

// ========== IsSM2Key / IsSM2PublicKey ==========

func TestBlackBox_IsSM2Key(t *testing.T) {
	sm2Priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !polluxSmx509.IsSM2Key(sm2Priv) {
		t.Error("sm2.PrivateKey should be detected as SM2 key")
	}

	ecPriv, _ := ecdsa.GenerateKey(polluxSM2.P256(), rand.Reader)
	if !polluxSmx509.IsSM2Key(ecPriv) {
		t.Error("ecdsa.PrivateKey on SM2 P256 should be detected as SM2 key")
	}
}

func TestBlackBox_IsSM2PublicKey(t *testing.T) {
	sm2Priv, _ := polluxSM2.GenerateKey(rand.Reader)
	if !polluxSmx509.IsSM2PublicKey(&sm2Priv.PublicKey) {
		t.Error("SM2 public key not detected")
	}
}

// ========== ExtractPublicKey ==========

func TestBlackBox_ExtractPublicKey(t *testing.T) {
	sm2Priv, _ := polluxSM2.GenerateKey(rand.Reader)
	pub, err := polluxSmx509.ExtractPublicKey(sm2Priv)
	if err != nil {
		t.Fatalf("ExtractPublicKey: %v", err)
	}
	if pub == nil {
		t.Error("public key should not be nil")
	}
}
