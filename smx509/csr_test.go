package smx509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
)

func TestCreateCertificateRequest_SM2(t *testing.T) {
	priv, err := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sm2Priv := new(sm2.PrivateKey)
	if _, err := sm2Priv.FromECPrivateKey(priv); err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "sm2-csr-test"},
		DNSNames: []string{"localhost"},
	}

	der, err := CreateCertificateRequest(tmpl, sm2Priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest SM2: %v", err)
	}
	if len(der) == 0 {
		t.Error("CSR DER should not be empty")
	}

	csr, err := ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if csr.Subject.CommonName != "sm2-csr-test" {
		t.Errorf("CommonName: got %q, want %q", csr.Subject.CommonName, "sm2-csr-test")
	}
}

func TestCreateCertificateRequest_RSA(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "rsa-csr-test"},
	}

	der, err := CreateCertificateRequest(tmpl, rsaPriv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest RSA: %v", err)
	}

	csr, err := ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if csr.Subject.CommonName != "rsa-csr-test" {
		t.Errorf("CommonName: got %q, want %q", csr.Subject.CommonName, "rsa-csr-test")
	}
}

func TestCheckCertificateRequestSignature(t *testing.T) {
	priv, err := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sm2Priv := new(sm2.PrivateKey)
	_, _ = sm2Priv.FromECPrivateKey(priv)

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "sig-check-test"},
	}

	der, err := CreateCertificateRequest(tmpl, sm2Priv)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}

	if err := CheckCertificateRequestSignature(csr); err != nil {
		t.Errorf("CheckCertificateRequestSignature: %v", err)
	}
}

// TestCheckCertificateRequestSignature_CorruptedECDSA 验证 ECDSA CSR 的
// 破坏签名被正确拒绝（回归保护）。
//
// 回归背景：CheckCertificateRequestSignature 对所有 stdlib 失败做 gmsm 重试，
// 但 gmsm 重试走 DER 往返（Raw 含原始有效签名），会从 DER 恢复有效签名，
// 掩盖内存中破坏的 Signature 字段 → 破坏签名被误判为有效。修复仅对
// ErrUnsupportedAlgorithm（SM2 OID）重试，其他错误直接返回。
func TestCheckCertificateRequestSignature_CorruptedECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "corrupted"}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	// 破坏内存中的签名字节
	csr.Signature = []byte{0x00, 0x01, 0x02}
	if err := CheckCertificateRequestSignature(csr); err == nil {
		t.Error("corrupted ECDSA CSR signature should be rejected, got nil")
	}
}

func TestParseCertificatePEM(t *testing.T) {
	priv, err := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sm2Priv := new(sm2.PrivateKey)
	_, _ = sm2Priv.FromECPrivateKey(priv)

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "pem-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := CreateCertificate(tmpl, tmpl, &priv.PublicKey, sm2Priv)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if pemData == nil {
		t.Fatal("pem.EncodeToMemory returned nil")
	}

	cert, err := ParseCertificatePEM(pemData)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	if cert.Subject.CommonName != "pem-test" {
		t.Errorf("CommonName: got %q, want %q", cert.Subject.CommonName, "pem-test")
	}
}

func TestParseCertificatePEM_Invalid(t *testing.T) {
	_, err := ParseCertificatePEM([]byte("not PEM data"))
	if err == nil {
		t.Error("should reject invalid PEM data")
	}
}

func TestVerify_NilCert(t *testing.T) {
	err := Verify(nil, VerifyOptions{})
	if err == nil {
		t.Error("should reject nil certificate")
	}
}

func TestVerifyDualCertSignatures_NilArgs(t *testing.T) {
	err := VerifyDualCertSignatures(nil, nil, VerifyOptions{})
	if err == nil {
		t.Error("should reject nil certificates")
	}
}

func TestVerifyDualCertSignatures_MismatchedCA(t *testing.T) {
	// 两个不同 CA 签发的证书
	priv1, _ := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	sm2Priv1 := new(sm2.PrivateKey)
	_, _ = sm2Priv1.FromECPrivateKey(priv1)

	priv2, _ := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	sm2Priv2 := new(sm2.PrivateKey)
	_, _ = sm2Priv2.FromECPrivateKey(priv2)

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	signTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "sign"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	signDER, _ := CreateCertificate(signTmpl, signTmpl, &priv1.PublicKey, sm2Priv1)
	signCert, _ := x509.ParseCertificate(signDER)

	encTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: "enc"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
	}
	encDER, _ := CreateCertificate(encTmpl, encTmpl, &priv2.PublicKey, sm2Priv2)
	encCert, _ := x509.ParseCertificate(encDER)

	err := VerifyDualCertSignatures(signCert, encCert, VerifyOptions{})
	if err == nil {
		t.Error("should reject mismatched CA certificates")
	}
}

func TestVerifyDualCertSignatures_InvalidKeyUsage(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	sm2Priv := new(sm2.PrivateKey)
	_, _ = sm2Priv.FromECPrivateKey(priv)

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// 两个证书都只有 KeyUsageDigitalSignature，加密证书缺少 keyEncipherment
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "both-sign"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, _ := CreateCertificate(tmpl, tmpl, &priv.PublicKey, sm2Priv)
	cert, _ := x509.ParseCertificate(der)

	err := VerifyDualCertSignatures(cert, cert, VerifyOptions{})
	if err == nil {
		t.Error("should reject certs with invalid key usage")
	}
}

// TestVerifyDualCertSignatures_SignatureVerification 锁定升级后的契约：
// 配对约束通过后，签名/证书链验证真实发生——正确信任锚下合法双证书对
// 返回 nil，无信任锚时必然失败（证明该函数验签名，而非只做结构检查）。
func TestVerifyDualCertSignatures_SignatureVerification(t *testing.T) {
	// 自签名 CA
	caPriv, _ := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	caSM2Priv := new(sm2.PrivateKey)
	_, _ = caSM2Priv.FromECPrivateKey(caPriv)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dual-sig-test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := CreateCertificate(caTmpl, caTmpl, &caPriv.PublicKey, caSM2Priv)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, err := ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	// 双证书对：同 subject、同 issuer、key usage 正确，均由 CA 签名
	priv, _ := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	sm2Priv := new(sm2.PrivateKey)
	_, _ = sm2Priv.FromECPrivateKey(priv)
	tmpl := func(serial int64, ku x509.KeyUsage) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "dual-sig-leaf"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     ku,
		}
	}
	signDER, err := CreateCertificate(tmpl(2, x509.KeyUsageDigitalSignature), caCert, &priv.PublicKey, caSM2Priv)
	if err != nil {
		t.Fatalf("create sign cert: %v", err)
	}
	signCert, err := ParseCertificate(signDER)
	if err != nil {
		t.Fatalf("parse sign cert: %v", err)
	}
	encDER, err := CreateCertificate(tmpl(3, x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment), caCert, &priv.PublicKey, caSM2Priv)
	if err != nil {
		t.Fatalf("create enc cert: %v", err)
	}
	encCert, err := ParseCertificate(encDER)
	if err != nil {
		t.Fatalf("parse enc cert: %v", err)
	}

	// 正确信任锚：签名链验证通过 → nil
	roots := NewCertPool()
	roots.AddCert(caCert)
	if err := VerifyDualCertSignatures(signCert, encCert, VerifyOptions{Roots: roots}); err != nil {
		t.Errorf("VerifyDualCertSignatures(valid pair, correct roots) = %v, want nil", err)
	}

	// 无信任锚：签名链无法建立 → 必须失败
	if err := VerifyDualCertSignatures(signCert, encCert, VerifyOptions{}); err == nil {
		t.Error("VerifyDualCertSignatures(valid pair, no roots) = nil, want error")
	}
}

// TestParseCertificateRequest_SM2EnumGuard 回归：fork 的 SM2WithSM3(17) 与
// Go 1.27 stdlib 的 MLDSA44(17) 数值相撞。fork CSR 转换为 stdlib 时，
// 超出共享前缀（PureEd25519=16）的枚举必须降级为 UnknownSignatureAlgorithm，
// 使 CheckCertificateRequestSignature 走 ErrUnsupportedAlgorithm → SM2 重试路径，
// 而非被 stdlib 当作 ML-DSA 校验报错。
func TestParseCertificateRequest_SM2EnumGuard(t *testing.T) {
	priv, err := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sm2Priv := new(sm2.PrivateKey)
	if _, err := sm2Priv.FromECPrivateKey(priv); err != nil {
		t.Fatal(err)
	}
	der, err := CreateCertificateRequest(&x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "enum-guard"},
	}, sm2Priv)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if csr.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		t.Errorf("fork SM2WithSM3 转换后应为 Unknown(0)，实际 %d（若为 17 说明被数值直拷为 MLDSA44，守卫失效）", int(csr.SignatureAlgorithm))
	}
	if err := CheckCertificateRequestSignature(csr); err != nil {
		t.Errorf("SM2 CSR 校验应经降级+重试路径成功: %v", err)
	}
}
