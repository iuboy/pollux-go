package crl

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	gmsmSmx509 "github.com/emmansun/gmsm/smx509"
	"github.com/iuboy/pollux-go/sm2"
	smx509 "github.com/iuboy/pollux-go/smx509"
)

// --- ReasonCode ---

func TestReasonCode_String(t *testing.T) {
	tests := []struct {
		code smx509.CRLReason
		want string
	}{
		{ReasonUnspecified, "unspecified"},
		{ReasonKeyCompromise, "keyCompromise"},
		{ReasonCACompromise, "cACompromise"},
		{ReasonAffiliationChanged, "affiliationChanged"},
		{ReasonSuperseded, "superseded"},
		{ReasonCessationOfOperation, "cessationOfOperation"},
		{ReasonCertificateHold, "certificateHold"},
		{ReasonRemoveFromCRL, "removeFromCRL"},
		{ReasonPrivilegeWithdrawn, "privilegeWithdrawn"},
		{ReasonAACompromise, "aACompromise"},
		{smx509.CRLReason(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.code.String(); got != tt.want {
				t.Errorf("ReasonCode(%d).String() = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

// TestReasonCode_RFC5280Values 锁定 RFC 5280 §5.3.1 的枚举数值。
// 值必须显式指定：iota 隐式编号会把 ReasonRemoveFromCRL 排到 7
// （RFC 保留 7 不用，removeFromCRL 必须为 8），序列化的 CRL reasonCode 扩展因此错误。
func TestReasonCode_RFC5280Values(t *testing.T) {
	cases := []struct {
		code smx509.CRLReason
		want int
	}{
		{ReasonUnspecified, 0},
		{ReasonKeyCompromise, 1},
		{ReasonCACompromise, 2},
		{ReasonAffiliationChanged, 3},
		{ReasonSuperseded, 4},
		{ReasonCessationOfOperation, 5},
		{ReasonCertificateHold, 6},
		{ReasonRemoveFromCRL, 8},
		{ReasonPrivilegeWithdrawn, 9},
		{ReasonAACompromise, 10},
	}
	for _, c := range cases {
		if int(c.code) != c.want {
			t.Errorf("%s = %d, want %d (RFC 5280 §5.3.1)", c.code, c.code, c.want)
		}
	}
}

// --- crlError ---

// --- memoryCRLCache ---

func TestMemoryCRLCache(t *testing.T) {
	cache := NewMemoryCRLCache()

	// 初始为空
	if cache.Get() != nil {
		t.Error("initial cache should be nil")
	}

	// Set + Get
	data := []byte("crl-data")
	cache.Set(data)

	got := cache.Get()
	if string(got) != "crl-data" {
		t.Error("cache Get returned wrong data")
	}

	// Clear
	cache.Clear()
	if cache.Get() != nil {
		t.Error("cache should be nil after Clear")
	}
}

func TestMemoryCRLCache_Concurrent(t *testing.T) {
	cache := NewMemoryCRLCache()
	var wg sync.WaitGroup
	wg.Add(2)

	// 并发读写
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			cache.Set([]byte{byte(i)})
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			cache.Get()
		}
	}()

	wg.Wait()
}

// --- createCRLReasonExtension ---

func TestCreateCRLReasonExtension(t *testing.T) {
	ext, err := smx509.CreateCRLReasonExtension(ReasonKeyCompromise)
	if err != nil {
		t.Fatal(err)
	}

	if !ext.Id.Equal([]int{2, 5, 29, 21}) {
		t.Error("wrong OID for reasonCode")
	}
	if ext.Critical {
		t.Error("reasonCode should not be critical")
	}

	// 验证 ASN.1 编码可以解析回来
	reason, found := smx509.ParseCRLReason([]pkix.Extension{ext})
	if !found {
		t.Fatal("ParseCRLReason should find the extension")
	}
	if reason != ReasonKeyCompromise {
		t.Errorf("got reason %d, want %d", reason, ReasonKeyCompromise)
	}
}

// --- createInvalidityDateExtension ---

func TestCreateInvalidityDateExtension(t *testing.T) {
	date := time.Date(2026, 3, 30, 12, 0, 0, 0, time.UTC)
	ext, err := smx509.CreateInvalidityDateExtension(date)
	if err != nil {
		t.Fatal(err)
	}

	if !ext.Id.Equal([]int{2, 5, 29, 24}) {
		t.Error("wrong OID for invalidityDate")
	}
	if ext.Critical {
		t.Error("invalidityDate should not be critical")
	}

	// 验证解析
	parsed, found := smx509.ParseInvalidityDate([]pkix.Extension{ext})
	if !found {
		t.Fatal("ParseInvalidityDate should find the extension")
	}
	if !parsed.Equal(date) {
		t.Errorf("got %v, want %v", parsed, date)
	}
}

// --- ParseCRLReason ---

func TestParseCRLReason_Found(t *testing.T) {
	ext, err := smx509.CreateCRLReasonExtension(ReasonCACompromise)
	if err != nil {
		t.Fatal(err)
	}
	reason, found := smx509.ParseCRLReason([]pkix.Extension{ext})

	if !found {
		t.Fatal("expected to find reason")
	}
	if reason != ReasonCACompromise {
		t.Errorf("got %d, want %d", reason, ReasonCACompromise)
	}
}

func TestParseCRLReason_NotFound(t *testing.T) {
	ext, err := smx509.CreateInvalidityDateExtension(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, found := smx509.ParseCRLReason([]pkix.Extension{ext})
	if found {
		t.Error("should not find reason in invalidityDate extension")
	}
}

func TestParseCRLReason_Empty(t *testing.T) {
	_, found := smx509.ParseCRLReason(nil)
	if found {
		t.Error("should not find reason in empty extensions")
	}
}

// --- ParseInvalidityDate ---

func TestParseInvalidityDate_Found(t *testing.T) {
	date := time.Date(2026, 1, 15, 8, 30, 0, 0, time.UTC)
	ext, err := smx509.CreateInvalidityDateExtension(date)
	if err != nil {
		t.Fatal(err)
	}
	parsed, found := smx509.ParseInvalidityDate([]pkix.Extension{ext})

	if !found {
		t.Fatal("expected to find invalidity date")
	}
	if !parsed.Equal(date) {
		t.Errorf("got %v, want %v", parsed, date)
	}
}

func TestParseInvalidityDate_NotFound(t *testing.T) {
	ext, err := smx509.CreateCRLReasonExtension(ReasonKeyCompromise)
	if err != nil {
		t.Fatal(err)
	}
	_, found := smx509.ParseInvalidityDate([]pkix.Extension{ext})
	if found {
		t.Error("should not find invalidityDate in reasonCode extension")
	}
}

func TestParseInvalidityDate_Empty(t *testing.T) {
	_, found := smx509.ParseInvalidityDate(nil)
	if found {
		t.Error("should not find date in empty extensions")
	}
}

// --- IsExpired ---

func TestIsExpired_NotExpired(t *testing.T) {
	// 测试空输入
	if !IsExpired(nil) {
		t.Error("nil CRL should be considered expired")
	}

	// 测试无效 PEM
	if !IsExpired([]byte("not a valid PEM")) {
		t.Error("invalid PEM should be considered expired")
	}

	// 测试错误类型
	block := &pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")}
	invalidPEM := pem.EncodeToMemory(block)
	if !IsExpired(invalidPEM) {
		t.Error("wrong PEM type should be considered expired")
	}
}

// --- GetRevokedSerials ---

func TestGetRevokedSerials_InvalidPEM(t *testing.T) {
	_, err := GetRevokedSerials(nil)
	if err == nil {
		t.Fatal("expected error for nil PEM")
	}

	_, err = GetRevokedSerials([]byte("invalid"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestGetRevokedSerials_WrongType(t *testing.T) {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: []byte("data")}
	_, err := GetRevokedSerials(pem.EncodeToMemory(block))
	if err == nil {
		t.Fatal("expected error for wrong PEM type")
	}
}

// --- GetCRLNumber ---

func TestGetCRLNumber_InvalidPEM(t *testing.T) {
	_, err := GetCRLNumber(nil)
	if err == nil {
		t.Fatal("expected error for nil PEM")
	}

	_, err = GetCRLNumber([]byte("invalid"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestGetCRLNumber_WrongType(t *testing.T) {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: []byte("data")}
	_, err := GetCRLNumber(pem.EncodeToMemory(block))
	if err == nil {
		t.Fatal("expected error for wrong PEM type")
	}
}

// --- NewGenerator ---

func TestNewGenerator(t *testing.T) {
	g := NewGenerator(nil, nil)
	if g == nil {
		t.Fatal("expected non-nil generator")
	}
}

// --- RevokedCertificate struct ---

func TestRevokedCertificate(t *testing.T) {
	rc := &RevokedCertificate{
		Serial:    "ABC123",
		Reason:    ReasonKeyCompromise,
		RevokedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if rc.Serial != "ABC123" {
		t.Error("Serial mismatch")
	}
	if rc.Reason != ReasonKeyCompromise {
		t.Error("Reason mismatch")
	}
}

// --- Integration: real CRL create + parse ---

func TestCRLIntegration_Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 创建自签名 CA 证书
	serial, _ := rand.Int(rand.Reader, big.NewInt(100000))
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * 365 * time.Hour),
		Subject:      pkix.Name{CommonName: "Test CA"},
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	// 创建 CRL
	revokedTemplate := &x509.RevocationList{
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   big.NewInt(12345),
				RevocationTime: time.Now().Add(-1 * time.Hour),
			},
		},
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-1 * time.Hour),
		NextUpdate: time.Now().Add(23 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, revokedTemplate, cert, priv)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	// 编码为 PEM
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

	// 解析验证
	serials, err := GetRevokedSerials(crlPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(serials) != 1 || serials[0] != "12345" {
		t.Errorf("expected [12345], got %v", serials)
	}

	num, err := GetCRLNumber(crlPEM)
	if err != nil {
		t.Fatal(err)
	}
	if num != 1 {
		t.Errorf("expected CRL number 1, got %d", num)
	}

	if IsExpired(crlPEM) {
		t.Error("CRL should not be expired")
	}
}

func TestCRLIntegration_WithReasonExtension(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	serial, _ := rand.Int(rand.Reader, big.NewInt(100000))
	certTemplate := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * 365 * time.Hour),
		Subject:      pkix.Name{CommonName: "Test CA"},
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, priv.Public(), priv)
	cert, _ := x509.ParseCertificate(certDER)

	// 使用 Go x509 原生的 ReasonCode 字段
	revokedEntry := x509.RevocationListEntry{
		SerialNumber:   big.NewInt(99999),
		RevocationTime: time.Now().Add(-2 * time.Hour),
		ReasonCode:     1, // x509.ReasonKeyCompromise
	}

	revokedTemplate := &x509.RevocationList{
		RevokedCertificateEntries: []x509.RevocationListEntry{revokedEntry},
		Number:                    big.NewInt(2),
		ThisUpdate:                time.Now().Add(-1 * time.Hour),
		NextUpdate:                time.Now().Add(23 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, revokedTemplate, cert, priv)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

	// 解析并验证撤销原因
	block, _ := pem.Decode(crlPEM)
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(crl.RevokedCertificateEntries))
	}

	entry := crl.RevokedCertificateEntries[0]
	if entry.ReasonCode != 1 {
		t.Errorf("expected ReasonCode 1 (KeyCompromise), got %d", entry.ReasonCode)
	}
}

// --- Integration: SM2 issuer (GM/T 0009-2012 SM2+SM3 CRL) ---
//
// 守护 crl.go 的 smx509.CreateRevocationList 分支：
// 当 issuer 是 SM2 私钥时，CRL 必须用 SM2+SM3 签名（GM/T 0009-2012）。

// sm2MockAuthority 实现 crl.Authority 接口，返回一个 SM2 CA。
type sm2MockAuthority struct {
	ca  *x509.Certificate
	key crypto.Signer
}

func (m *sm2MockAuthority) GetRevokedList(_ context.Context) ([]*RevokedCertificate, error) {
	return []*RevokedCertificate{
		{
			Serial:    "123", // 十进制（authority 以 cert.SerialNumber.String() 存储）
			Reason:    ReasonKeyCompromise,
			RevokedAt: time.Now().Add(-2 * time.Hour).UTC(),
		},
		{
			Serial:    "255", // 十进制
			Reason:    ReasonSuperseded,
			RevokedAt: time.Now().Add(-1 * time.Hour).UTC(),
		},
	}, nil
}

func (m *sm2MockAuthority) GetRevokedListByIssuer(_ context.Context, _ string) ([]*RevokedCertificate, error) {
	return m.GetRevokedList(context.Background())
}

func (m *sm2MockAuthority) GetCertificateChain() []*x509.Certificate {
	return []*x509.Certificate{m.ca}
}

func (m *sm2MockAuthority) GetIntermediateCA() *x509.Certificate {
	return m.ca
}

func (m *sm2MockAuthority) GetIntermediateKey() crypto.Signer {
	return m.key
}

func TestCRLIntegration_SM2(t *testing.T) {
	// 1. 生成 SM2 私钥
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate SM2 key: %v", err)
	}

	// 2. 创建自签名 SM2 CA 证书（必须用 pollux-go/smx509.CreateCertificate
	//    走 gmsm 后端，而非 stdlib x509.CreateCertificate）
	serial, _ := rand.Int(rand.Reader, big.NewInt(100000))
	caTemplate := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * 365 * time.Hour),
		Subject:               pkix.Name{CommonName: "Test SM2 CA"},
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
	}

	certDER, err := smx509.CreateCertificate(caTemplate, caTemplate, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create SM2 CA cert: %v", err)
	}
	// 用 pollux-go/smx509.ParseCertificate 解析（gmsm 后端支持 SM2 曲线，
	// stdlib x509.ParseCertificate 会报 "unsupported elliptic curve"）。
	caCert, err := smx509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse SM2 CA cert: %v", err)
	}

	// 3. 组装 mock Authority 并生成 CRL
	auth := &sm2MockAuthority{ca: caCert, key: priv}
	gen := NewGenerator(auth, NewMemoryCRLCache())

	ctx := context.Background()
	crlPEM, err := gen.Generate(ctx)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// 断言 1: CRL PEM 非空
	if len(crlPEM) == 0 {
		t.Fatal("expected non-empty CRL PEM")
	}

	// 解析 CRL DER。必须用 gmsm/smx509.ParseRevocationList：stdlib 的
	// x509.ParseRevocationList 不认识 SM2 签名算法 OID，会把
	// SignatureAlgorithm 解析成 UnknownSignatureAlgorithm（值 0）。
	block, _ := pem.Decode(crlPEM)
	if block == nil || block.Type != "X509 CRL" {
		t.Fatalf("invalid CRL PEM block: %+v", block)
	}

	crl, err := gmsmSmx509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CRL via gmsm/smx509: %v", err)
	}

	// 断言 2: 签名算法是 SM2（SM2WithSM3 == 99）
	if crl.SignatureAlgorithm != gmsmSmx509.SM2WithSM3 {
		t.Errorf("expected SM2WithSM3 signature algorithm, got %v", crl.SignatureAlgorithm)
	}

	// 断言 3: 用 SM2 CA 公钥验签通过（确认是 SM2+SM3 真实签名）
	if err := crl.CheckSignatureFrom(toGmsmCert(caCert)); err != nil {
		t.Errorf("CRL signature verification failed: %v", err)
	}

	// 断言 4: 撤销条目数量正确（2 条）
	if got := len(crl.RevokedCertificateEntries); got != 2 {
		t.Errorf("expected 2 revoked entries, got %d", got)
	}

	// 断言 5: CRL Number 非零（Generate 自动递增哨兵）
	num, err := GetCRLNumber(crlPEM)
	if err != nil {
		t.Fatalf("GetCRLNumber failed: %v", err)
	}
	if num == 0 {
		t.Error("expected non-zero CRL number")
	}
}

// toGmsmCert 将 crypto/x509.Certificate 转换为 gmsm/smx509.Certificate，
// 以便调用 gmsm 的 CheckSignatureFrom（CRL 验签路径需要 gmsm 端的类型）。
//
// gmsm v0.44 起 smx509.Certificate 不再是 x509.Certificate 的命名类型别名
// （直接类型转换 / struct 拷贝均失效），改为经 Raw DER 往返（无损）。
func toGmsmCert(c *x509.Certificate) *gmsmSmx509.Certificate {
	if c == nil || len(c.Raw) == 0 {
		return nil
	}
	gc, err := gmsmSmx509.ParseCertificate(c.Raw)
	if err != nil {
		return nil
	}
	return gc
}
