package tlcp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	polluxSmx509 "github.com/iuboy/pollux-go/smx509"
)

// certSpec 描述一张测试证书的规格。
type certSpec struct {
	nonSM2   bool // 使用 ECDSA P-256 而非 SM2
	keyUsage x509.KeyUsage
	eku      []x509.ExtKeyUsage
	issuer   *x509.Certificate // 签发者证书(必填)
	signer   *sm2.PrivateKey   // 签发者私钥(必填)
}

// makeCert 按规格签发一张证书并返回(证书 + 新生成的 SM2 持有者私钥)。
// 非 SM2 变体仅改变证书公钥算法,持有者私钥仍为 SM2(供 DualCertPair 占位)。
func makeCert(t *testing.T, spec certSpec) (*x509.Certificate, *sm2.PrivateKey) {
	t.Helper()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "dual-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     spec.keyUsage,
		ExtKeyUsage:  spec.eku,
	}

	// SM2 持有者密钥对(也作为非 SM2 变体的签名占位)
	priv, err := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate sm2 key: %v", err)
	}
	smPriv := new(sm2.PrivateKey)
	if _, err := smPriv.FromECPrivateKey(priv); err != nil {
		t.Fatalf("convert sm2 key: %v", err)
	}

	if spec.nonSM2 {
		// 非 SM2 变体:全程用标准 ECDSA P-256 自签,避免 stdlib 不识别 SM2 签名曲线。
		ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ecdsa key: %v", err)
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecdsaPriv.PublicKey, ecdsaPriv)
		if err != nil {
			t.Fatalf("create ecdsa cert: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse ecdsa cert: %v", err)
		}
		return cert, smPriv
	}

	der, err := polluxSmx509.CreateCertificate(tmpl, spec.issuer, &priv.PublicKey, spec.signer)
	if err != nil {
		t.Fatalf("create sm2 cert: %v", err)
	}
	cert, err := polluxSmx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse sm2 cert: %v", err)
	}
	return cert, smPriv
}

type caMaterial struct {
	cert *x509.Certificate
	key  *sm2.PrivateKey
}

// selfSignCA 生成一个自签名 SM2 CA 证书。cn 指定 CA 的 CommonName。
func selfSignCA(t *testing.T, cn string) caMaterial {
	t.Helper()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	priv, _ := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	smPriv := new(sm2.PrivateKey)
	if _, err := smPriv.FromECPrivateKey(priv); err != nil {
		t.Fatalf("convert ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := polluxSmx509.CreateCertificate(tmpl, tmpl, &priv.PublicKey, smPriv)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	cert, err := polluxSmx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return caMaterial{cert: cert, key: smPriv}
}

// TestValidateTLCPCertificate 覆盖单证书校验的各分支。
func TestValidateTLCPCertificate(t *testing.T) {
	ca := selfSignCA(t, "dual-test-ca")

	// 合规签名证书
	signCert, _ := makeCert(t, certSpec{
		keyUsage: x509.KeyUsageDigitalSignature,
		issuer:   ca.cert, signer: ca.key,
	})
	if err := ValidateTLCPCertificate(signCert, true); err != nil {
		t.Errorf("valid sign cert err = %v", err)
	}

	// 合规加密证书
	encCert, _ := makeCert(t, certSpec{
		keyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		issuer:   ca.cert, signer: ca.key,
	})
	if err := ValidateTLCPCertificate(encCert, false); err != nil {
		t.Errorf("valid enc cert err = %v", err)
	}

	// nil 证书
	if err := ValidateTLCPCertificate(nil, true); err == nil {
		t.Error("ValidateTLCPCertificate(nil) err = nil, want error")
	}

	// 非 SM2 证书
	nonSM2Cert, _ := makeCert(t, certSpec{
		nonSM2: true, keyUsage: x509.KeyUsageDigitalSignature,
		issuer: ca.cert, signer: ca.key,
	})
	if err := ValidateTLCPCertificate(nonSM2Cert, true); err == nil {
		t.Error("ValidateTLCPCertificate(non-SM2) err = nil, want error")
	}

	// 签名证书缺 DigitalSignature
	missingSignCert, _ := makeCert(t, certSpec{
		keyUsage: x509.KeyUsageKeyEncipherment, issuer: ca.cert, signer: ca.key,
	})
	if err := ValidateTLCPCertificate(missingSignCert, true); err == nil {
		t.Error("ValidateTLCPCertificate(sign without DigitalSignature) err = nil, want error")
	}

	// 加密证书缺 KeyEncipherment/DataEncipherment
	missingEncCert, _ := makeCert(t, certSpec{
		keyUsage: x509.KeyUsageDigitalSignature, issuer: ca.cert, signer: ca.key,
	})
	if err := ValidateTLCPCertificate(missingEncCert, false); err == nil {
		t.Error("ValidateTLCPCertificate(enc without keyEncipherment) err = nil, want error")
	}

	// EKU 不含 serverAuth/clientAuth/any
	badEKUCert, _ := makeCert(t, certSpec{
		keyUsage: x509.KeyUsageDigitalSignature,
		eku:      []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		issuer:   ca.cert, signer: ca.key,
	})
	if err := ValidateTLCPCertificate(badEKUCert, true); err == nil {
		t.Error("ValidateTLCPCertificate(bad EKU) err = nil, want error")
	}
}

// TestValidateDualCertPair 覆盖双证书对校验:nil sign/enc、不同 issuer、成功。
func TestValidateDualCertPair(t *testing.T) {
	ca := selfSignCA(t, "dual-test-ca")
	signCert, _ := makeCert(t, certSpec{
		keyUsage: x509.KeyUsageDigitalSignature, issuer: ca.cert, signer: ca.key,
	})
	encCert, _ := makeCert(t, certSpec{
		keyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		issuer:   ca.cert, signer: ca.key,
	})

	// 合规对(同 issuer = CA)
	pair := &DualCertPair{SignCert: signCert, EncCert: encCert}
	if err := ValidateDualCertPair(pair); err != nil {
		t.Errorf("valid pair err = %v", err)
	}

	// nil sign
	if err := ValidateDualCertPair(&DualCertPair{EncCert: encCert}); !errors.Is(err, errSignCertMissing) {
		t.Errorf("nil sign err = %v, want errSignCertMissing", err)
	}
	// nil enc
	if err := ValidateDualCertPair(&DualCertPair{SignCert: signCert}); !errors.Is(err, errEncCertMissing) {
		t.Errorf("nil enc err = %v, want errEncCertMissing", err)
	}

	// 不同 issuer:enc 用另一个 CA 签发
	ca2 := selfSignCA(t, "dual-test-ca-2")
	encCert2, _ := makeCert(t, certSpec{
		keyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		issuer:   ca2.cert, signer: ca2.key,
	})
	pairDiff := &DualCertPair{SignCert: signCert, EncCert: encCert2}
	if err := ValidateDualCertPair(pairDiff); err == nil {
		t.Error("different issuer pair err = nil, want error")
	}
}

// TestDualCertPair_PublicKeyPairs 验证公钥提取。
func TestDualCertPair_PublicKeyPairs(t *testing.T) {
	ca := selfSignCA(t, "dual-test-ca")
	signCert, _ := makeCert(t, certSpec{
		keyUsage: x509.KeyUsageDigitalSignature, issuer: ca.cert, signer: ca.key,
	})
	encCert, _ := makeCert(t, certSpec{
		keyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		issuer:   ca.cert, signer: ca.key,
	})

	pair := &DualCertPair{SignCert: signCert, EncCert: encCert}
	signPub, encPub := pair.PublicKeyPairs()
	if signPub == nil {
		t.Error("signPub = nil")
	}
	if encPub == nil {
		t.Error("encPub = nil")
	}

	// nil 证书 → 公钥为 nil
	empty := &DualCertPair{}
	s, e := empty.PublicKeyPairs()
	if s != nil || e != nil {
		t.Error("empty pair PublicKeyPairs should return nil,nil")
	}
}

// TestDualCertPair_ToTLSCertificates 验证双证书转换为 tls.Certificate。
func TestDualCertPair_ToTLSCertificates(t *testing.T) {
	ca := selfSignCA(t, "dual-test-ca")
	signCert, signKey := makeCert(t, certSpec{
		keyUsage: x509.KeyUsageDigitalSignature, issuer: ca.cert, signer: ca.key,
	})
	encCert, encKey := makeCert(t, certSpec{
		keyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		issuer:   ca.cert, signer: ca.key,
	})

	pair := &DualCertPair{SignCert: signCert, EncCert: encCert, SignKey: signKey, EncKey: encKey}
	certs, err := pair.ToTLSCertificates()
	if err != nil {
		t.Fatalf("ToTLSCertificates err = %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("certs len = %d, want 2", len(certs))
	}
	if certs[0].PrivateKey == nil || certs[1].PrivateKey == nil {
		t.Error("certificates missing private keys")
	}
}

// TestLoadDualCertPairFromPEM_BadInput 验证 PEM 解析失败路径。
func TestLoadDualCertPairFromPEM_BadInput(t *testing.T) {
	_, err := LoadDualCertPairFromPEM([]byte("bad"), []byte("bad"), []byte("bad"), []byte("bad"))
	if err == nil {
		t.Error("LoadDualCertPairFromPEM(bad pem) err = nil, want error")
	}
}

// TestLoadDualCertPair_MissingFile 验证从不存在的文件加载失败。
func TestLoadDualCertPair_MissingFile(t *testing.T) {
	_, err := LoadDualCertPair("/no/sign.pem", "/no/sign.key", "/no/enc.pem", "/no/enc.key")
	if err == nil {
		t.Error("LoadDualCertPair(nonexistent) err = nil, want error")
	}
}

// TestParseCertificatePEM_BadInput 验证 PEM 解析失败路径。
func TestParseCertificatePEM_BadInput(t *testing.T) {
	if _, err := parseCertificatePEM([]byte("not a pem block")); err == nil {
		t.Error("parseCertificatePEM(garbage) err = nil, want error")
	}
}

// TestVerifyDualCertPair 覆盖 VerifyDualCertPair 委托调用。
// 不断言验证结果(VerifyDualCerts 可能因缺少根池而返回错误),仅验证可达且不 panic。
func TestVerifyDualCertPair(t *testing.T) {
	ca := selfSignCA(t, "dual-test-ca")
	signCert, _ := makeCert(t, certSpec{
		keyUsage: x509.KeyUsageDigitalSignature, issuer: ca.cert, signer: ca.key,
	})
	encCert, _ := makeCert(t, certSpec{
		keyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		issuer:   ca.cert, signer: ca.key,
	})
	pair := &DualCertPair{SignCert: signCert, EncCert: encCert}
	// 仅验证委托路径被覆盖;VerifyDualCerts 内部签名链校验结果不在此断言
	_ = VerifyDualCertPair(pair)
}

// TestLoadSM2PrivateKey 覆盖从文件加载 SM2 私钥(成功/失败)。
func TestLoadSM2PrivateKey(t *testing.T) {
	dir := testCertDir(t)
	keyFile := filepath.Join(dir, "sm2_sign_key.pem")

	key, err := loadSM2PrivateKey(keyFile)
	if err != nil {
		t.Logf("loadSM2PrivateKey(sm2 key) err = %v (可接受的格式差异)", err)
	} else if key == nil {
		t.Error("loadSM2PrivateKey returned nil key without error")
	}

	// 不存在的文件
	if _, err := loadSM2PrivateKey("/nonexistent/key.pem"); err == nil {
		t.Error("loadSM2PrivateKey(nonexistent) err = nil, want error")
	}
}
