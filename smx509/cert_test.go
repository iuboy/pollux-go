package smx509

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	gmsmSMX509 "github.com/emmansun/gmsm/smx509"
)

func generateSM2Cert(t *testing.T) (*x509.Certificate, *sm2.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	sm2Priv := new(sm2.PrivateKey)
	if _, err := sm2Priv.FromECPrivateKey(priv); err != nil {
		t.Fatalf("convert SM2 key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour * 24),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	der, err := CreateCertificate(tmpl, tmpl, &priv.PublicKey, sm2Priv)
	if err != nil {
		t.Fatalf("CreateCertificate SM2: %v", err)
	}

	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, sm2Priv
}

func TestIsSM2Key(t *testing.T) {
	_, sm2Priv := generateSM2Cert(t)
	if !IsSM2Key(sm2Priv) {
		t.Error("sm2.PrivateKey should be recognized as SM2")
	}

	ecdsaPriv, _ := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if !IsSM2Key(ecdsaPriv) {
		t.Error("ecdsa.PrivateKey on SM2 curve should be recognized as SM2")
	}

	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if IsSM2Key(rsaPriv) {
		t.Error("RSA key should not be recognized as SM2")
	}
}

func TestIsSM2PublicKey(t *testing.T) {
	_, sm2Priv := generateSM2Cert(t)
	if !IsSM2PublicKey(&sm2Priv.PublicKey) {
		t.Error("SM2 public key should be recognized")
	}

	ecdsaPriv, _ := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if !IsSM2PublicKey(&ecdsaPriv.PublicKey) {
		t.Error("ECDSA public key on SM2 curve should be recognized")
	}

	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if IsSM2PublicKey(rsaPriv.Public()) {
		t.Error("RSA public key should not be recognized as SM2")
	}
}

func TestParseCertificate_SM2(t *testing.T) {
	cert, _ := generateSM2Cert(t)
	if cert == nil {
		t.Fatal("cert should not be nil")
	}
	if cert.Subject.CommonName != "test" {
		t.Errorf("CommonName: got %q, want %q", cert.Subject.CommonName, "test")
	}
}

func TestParseCertificate_InvalidDER(t *testing.T) {
	_, err := ParseCertificate([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Error("should reject invalid DER")
	}
}

func TestCreateCertificate_RSA(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "rsa-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := CreateCertificate(tmpl, tmpl, &rsaPriv.PublicKey, rsaPriv)
	if err != nil {
		t.Fatalf("CreateCertificate RSA: %v", err)
	}
	if len(der) == 0 {
		t.Error("DER should not be empty")
	}
}

func TestExtractPublicKey(t *testing.T) {
	_, sm2Priv := generateSM2Cert(t)
	pub, err := ExtractPublicKey(sm2Priv)
	if err != nil {
		t.Fatalf("ExtractPublicKey SM2: %v", err)
	}
	if pub == nil {
		t.Error("public key should not be nil")
	}

	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub, err = ExtractPublicKey(rsaPriv)
	if err != nil {
		t.Fatalf("ExtractPublicKey RSA: %v", err)
	}
	if pub == nil {
		t.Error("public key should not be nil")
	}

	_, ed25519Priv, _ := ed25519.GenerateKey(rand.Reader)
	_, err = ExtractPublicKey(ed25519Priv)
	if err != nil {
		t.Fatalf("ExtractPublicKey Ed25519: %v", err)
	}
}

func TestSignatureAlgorithmForPrivateKey(t *testing.T) {
	_, sm2Priv := generateSM2Cert(t)
	if algo := SignatureAlgorithmForPrivateKey(sm2Priv); algo != x509.UnknownSignatureAlgorithm {
		t.Errorf("SM2 should return UnknownSignatureAlgorithm, got %v", algo)
	}

	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if algo := SignatureAlgorithmForPrivateKey(rsaPriv); algo != x509.SHA256WithRSA {
		t.Errorf("RSA 2048 should return SHA256WithRSA, got %v", algo)
	}

	ecdsaPriv, _ := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if algo := SignatureAlgorithmForPrivateKey(ecdsaPriv); algo != x509.UnknownSignatureAlgorithm {
		t.Errorf("SM2 curve ECDSA should return UnknownSignatureAlgorithm, got %v", algo)
	}
}

func TestPublicKeyAlgorithmForPrivateKey(t *testing.T) {
	_, sm2Priv := generateSM2Cert(t)
	if algo := PublicKeyAlgorithmForPrivateKey(sm2Priv); algo != x509.ECDSA {
		t.Errorf("SM2 should return ECDSA, got %v", algo)
	}

	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if algo := PublicKeyAlgorithmForPrivateKey(rsaPriv); algo != x509.RSA {
		t.Errorf("RSA should return RSA, got %v", algo)
	}
}

func TestMarshalPKIXPublicKey(t *testing.T) {
	_, sm2Priv := generateSM2Cert(t)
	der, err := MarshalPKIXPublicKey(&sm2Priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	if len(der) == 0 {
		t.Error("DER should not be empty")
	}
}

// TestParsePKIXPublicKeyRoundTrip 验证 MarshalPKIXPublicKey → ParsePKIXPublicKey
// 的 round-trip,覆盖 SM2、标准 ECDSA(P-256)、RSA、Ed25519。这是 ParsePKIXPublicKey
// 的核心契约:它必须能解析本包 MarshalPKIXPublicKey 产出的 DER,补全 marshal/parse
// 的对称缺口。
func TestParsePKIXPublicKeyRoundTrip(t *testing.T) {
	// SM2 公钥(来自证书辅助生成的密钥)
	_, sm2Priv := generateSM2Cert(t)

	// 标准 ECDSA P-256 公钥
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// RSA 公钥
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Ed25519 公钥
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		pub  any
		// 期望解析结果的类型断言
		assert func(t *testing.T, parsed any, original any)
	}{
		{
			name: "SM2",
			pub:  &sm2Priv.PublicKey,
			assert: func(t *testing.T, parsed, original any) {
				got, ok := parsed.(*ecdsa.PublicKey)
				want := original.(*ecdsa.PublicKey)
				if !ok {
					t.Fatalf("SM2: parsed type = %T, want *ecdsa.PublicKey", parsed)
				}
				if got.Curve != sm2.P256() {
					t.Errorf("SM2: parsed curve = %v, want SM2 P256", got.Curve)
				}
				if got.X.Cmp(want.X) != 0 || got.Y.Cmp(want.Y) != 0 {
					t.Error("SM2: parsed point mismatch")
				}
			},
		},
		{
			name: "ECDSA_P256",
			pub:  &ecdsaPriv.PublicKey,
			assert: func(t *testing.T, parsed, original any) {
				got, ok := parsed.(*ecdsa.PublicKey)
				want := original.(*ecdsa.PublicKey)
				if !ok {
					t.Fatalf("ECDSA: parsed type = %T, want *ecdsa.PublicKey", parsed)
				}
				if got.X.Cmp(want.X) != 0 || got.Y.Cmp(want.Y) != 0 {
					t.Error("ECDSA: parsed point mismatch")
				}
			},
		},
		{
			name: "RSA",
			pub:  &rsaPriv.PublicKey,
			assert: func(t *testing.T, parsed, original any) {
				got, ok := parsed.(*rsa.PublicKey)
				want := original.(*rsa.PublicKey)
				if !ok {
					t.Fatalf("RSA: parsed type = %T, want *rsa.PublicKey", parsed)
				}
				if got.N.Cmp(want.N) != 0 || got.E != want.E {
					t.Error("RSA: parsed modulus/exponent mismatch")
				}
			},
		},
		{
			name: "Ed25519",
			pub:  edPub,
			assert: func(t *testing.T, parsed, original any) {
				got, ok := parsed.(ed25519.PublicKey)
				want := original.(ed25519.PublicKey)
				if !ok {
					t.Fatalf("Ed25519: parsed type = %T, want ed25519.PublicKey", parsed)
				}
				if !bytes.Equal(got, want) {
					t.Error("Ed25519: parsed bytes mismatch")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			der, err := MarshalPKIXPublicKey(tc.pub)
			if err != nil {
				t.Fatalf("MarshalPKIXPublicKey: %v", err)
			}
			parsed, err := ParsePKIXPublicKey(der)
			if err != nil {
				t.Fatalf("ParsePKIXPublicKey: %v", err)
			}
			tc.assert(t, parsed, tc.pub)
		})
	}
}

// TestParsePKIXPublicKey_InvalidDER 验证垃圾输入返回 error 而非 panic。
func TestParsePKIXPublicKey_InvalidDER(t *testing.T) {
	_, err := ParsePKIXPublicKey([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Error("ParsePKIXPublicKey should reject garbage DER")
	}
	_, err = ParsePKIXPublicKey(nil)
	if err == nil {
		t.Error("ParsePKIXPublicKey should reject nil input")
	}
}

func TestMarshalParseECPrivateKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}

	parsed, err := ParseECPrivateKey(der)
	if err != nil {
		t.Fatalf("ParseECPrivateKey: %v", err)
	}
	if parsed.X.Cmp(priv.X) != 0 || parsed.Y.Cmp(priv.Y) != 0 {
		t.Error("parsed key mismatch")
	}
}

// TestCopyCertFields_EnumGuardAndDriftReporting 锁定枚举守卫语义：
// 共享前缀外的枚举值在转换时降级/丢弃并经 CopyFieldDriftHook 上报，
// 共享前缀内的值原样通过且不触发 hook。
func TestCopyCertFields_EnumGuardAndDriftReporting(t *testing.T) {
	var drift []string
	CopyFieldDriftHook = func(skipped []string) { drift = append(drift, skipped...) }
	defer func() { CopyFieldDriftHook = nil }()

	mentions := func(sub string) bool {
		for _, d := range drift {
			if strings.Contains(d, sub) {
				return true
			}
		}
		return false
	}

	// stdlib -> smx509：值 17 在 Go 1.27 stdlib 是 MLDSA44，与 fork 的
	// SM2WithSM3 相撞，超出共享前缀（0..16）必须降级为 Unknown；
	// ExtKeyUsage=99 超出 0..13，该元素必须被丢弃（而非误映射）。
	tmpl := &x509.Certificate{
		SignatureAlgorithm: x509.SignatureAlgorithm(17),
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsage(99)},
	}
	sm, err := ToSMX509Certificate(tmpl)
	if err != nil {
		t.Fatalf("ToSMX509Certificate: %v", err)
	}
	if sm.SignatureAlgorithm != gmsmSMX509.UnknownSignatureAlgorithm {
		t.Errorf("out-of-range SignatureAlgorithm must downgrade to Unknown, got %d", sm.SignatureAlgorithm)
	}
	if len(sm.ExtKeyUsage) != 1 || sm.ExtKeyUsage[0] != gmsmSMX509.ExtKeyUsageServerAuth {
		t.Errorf("out-of-range ExtKeyUsage element must be dropped, got %v", sm.ExtKeyUsage)
	}
	if !mentions("SignatureAlgorithm=17") || !mentions("ExtKeyUsage[1]=99") {
		t.Errorf("drift hook must report enum downgrades, got %v", drift)
	}

	// 反向：fork 的 SM2WithSM3(17) 转 stdlib 同样降级为 Unknown 并上报。
	drift = nil
	smCert := &gmsmSMX509.Certificate{SignatureAlgorithm: gmsmSMX509.SM2WithSM3}
	std, err := ToStdCertificate(smCert)
	if err != nil {
		t.Fatalf("ToStdCertificate: %v", err)
	}
	if std.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		t.Errorf("fork-only SignatureAlgorithm must downgrade to Unknown, got %d", std.SignatureAlgorithm)
	}
	if !mentions("SignatureAlgorithm=17") {
		t.Errorf("drift hook must report fork-only SignatureAlgorithm, got %v", drift)
	}

	// 共享前缀内的值不受影响、不触发枚举降级上报（其余字段漂移——如
	// stdlib 新增字段在 fork 侧缺失——不属于枚举守卫，允许出现）。
	drift = nil
	ok := &x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageOCSPSigning},
	}
	smOK, err := ToSMX509Certificate(ok)
	if err != nil {
		t.Fatalf("ToSMX509Certificate: %v", err)
	}
	if smOK.SignatureAlgorithm != gmsmSMX509.ECDSAWithSHA256 {
		t.Errorf("shared-range SignatureAlgorithm must pass through, got %d", smOK.SignatureAlgorithm)
	}
	if len(smOK.ExtKeyUsage) != 2 {
		t.Errorf("shared-range ExtKeyUsage must pass through, got %v", smOK.ExtKeyUsage)
	}
	if mentions("outside shared range") {
		t.Errorf("shared-range enums must not report downgrades, got %v", drift)
	}
}

// TestVerifySM2_ExtKeyUsageOutOfRange 锁定 verifySM2 的 ExtKeyUsage 范围
// 守卫：超出共享前缀（0..maxSharedExtKeyUsage）的值不得盲转换，须返回
// 显式错误。叶子必须非自签且不在 Roots 中——Go stdlib 对 Root 池内的
// 证书走免验签信任锚快速路径，不会进入 SM2 分支。
func TestVerifySM2_ExtKeyUsageOutOfRange(t *testing.T) {
	_, _, leafGmsm, rootPool := buildCertChain(t)
	leaf := smToStdCert(t, leafGmsm)
	err := Verify(leaf, VerifyOptions{
		Roots:     rootPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsage(99)},
	})
	if err == nil || !strings.Contains(err.Error(), "outside shared ExtKeyUsage range") {
		t.Fatalf("expected ExtKeyUsage range-guard error, got %v", err)
	}
}

// TestToSMX509Certificate_RawBothBackendsFail 锁定 ToSMX509Certificate 的
// 双后端错误合并：Raw 非空但 gmsm 与 stdlib 都解析失败时，返回的错误必须
// 携带两个后端的错误（errors.Join，对齐 ParseCertificate 的既有模式）。
// 注：现代 crypto/x509 对畸形输入返回非类型化错误（errors.New），故此处
// 断言错误内容而非 errors.As。
func TestToSMX509Certificate_RawBothBackendsFail(t *testing.T) {
	// 合法 ASN.1 SEQUENCE 但不是证书：两个解析器都必须拒绝。
	bad := &x509.Certificate{Raw: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}
	_, err := ToSMX509Certificate(bad)
	if err == nil {
		t.Fatal("expected error for non-certificate Raw DER")
	}
	if !strings.Contains(err.Error(), "failed to parse certificate from Raw") {
		t.Fatalf("error should carry the wrap prefix, got: %v", err)
	}
	// errors.Join 以换行拼接两个后端错误：两行都须存在（gmsm 与 stdlib 的
	// 文本此处相同，均为 "x509: malformed tbs certificate" 风格）。
	if got := strings.Count(err.Error(), "x509: malformed"); got != 2 {
		t.Fatalf("joined error should carry both backends' errors, found %d: %v", got, err)
	}
}
