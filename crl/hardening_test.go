package crl

// 安全加固回归测试(第二轮审查 M-4/M-5/M-6/M-7 与 fanout L-4/L-5 修复)。

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/sm2"
	"github.com/iuboy/pollux-go/smx509"
)

// countableAuthority 记录回源次数,用于验证空切片回源语义。
type countableAuthority struct {
	sm2MockAuthority
	fetches int
}

func (m *countableAuthority) GetRevokedList(ctx context.Context) ([]*RevokedCertificate, error) {
	m.fetches++
	return m.sm2MockAuthority.GetRevokedList(ctx)
}

// newHardeningAuth 构造带 SM2 CA 的可计数 mock authority。
func newHardeningAuth(t *testing.T) *countableAuthority {
	t.Helper()
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(100000))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * 365 * time.Hour),
		Subject:               pkix.Name{CommonName: "Hardening Test CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := smx509.CreateCertificate(tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	ca, err := smx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &countableAuthority{sm2MockAuthority: sm2MockAuthority{ca: ca, key: priv}}
}

// TestGenerateWithOptions_EmptySliceFallsBackToStore 锁定 M-5 修复:
// 空(非 nil)撤销列表必须回源存储——否则误传空切片会签发"空名单"权威
// CRL,所有已撤销证书在依赖方恢复有效。
func TestGenerateWithOptions_EmptySliceFallsBackToStore(t *testing.T) {
	auth := newHardeningAuth(t)
	gen := NewGenerator(auth, NewMemoryCRLCache())

	// 传空切片(JSON 反序列化常见产物):必须回源拿到真实撤销记录。
	pem, err := gen.GenerateWithOptions(context.Background(), &GenerateOptions{
		RevokedCertificates: []*RevokedCertificate{}, // 非 nil 空切片
	})
	if err != nil {
		t.Fatalf("GenerateWithOptions(空切片): %v", err)
	}
	if auth.fetches != 1 {
		t.Fatalf("空切片应回源存储(1 次),实际回源 %d 次", auth.fetches)
	}
	serials, err := GetRevokedSerials(pem)
	if err != nil {
		t.Fatal(err)
	}
	if len(serials) != 2 {
		t.Fatalf("回源后 CRL 应含 2 条撤销记录, got %d", len(serials))
	}

	// 非空列表不回源(直传语义)。
	pem2, err := gen.GenerateWithOptions(context.Background(), &GenerateOptions{
		RevokedCertificates: []*RevokedCertificate{
			{Serial: "777", Reason: ReasonSuperseded, RevokedAt: time.Now().UTC()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if auth.fetches != 1 { // 仍是 1,未再回源
		t.Fatalf("显式列表不应回源,fetches=%d", auth.fetches)
	}
	s2, _ := GetRevokedSerials(pem2)
	if len(s2) != 1 || s2[0] != "777" {
		t.Fatalf("直传列表未生效: %v", s2)
	}
}

// TestGenerateWithOptions_InvalidSerialRejected 锁定 M-6 修复:
// 非法/非正数序列号必须拒绝整轮签发(fail-closed),不得静默跳过。
func TestGenerateWithOptions_InvalidSerialRejected(t *testing.T) {
	auth := newHardeningAuth(t)
	gen := NewGenerator(auth, NewMemoryCRLCache())

	for _, bad := range []string{"xyz", "-5", "0", ""} {
		_, err := gen.GenerateWithOptions(context.Background(), &GenerateOptions{
			RevokedCertificates: []*RevokedCertificate{
				{Serial: "123", Reason: ReasonKeyCompromise, RevokedAt: time.Now().UTC()},
				{Serial: bad, Reason: ReasonSuperseded, RevokedAt: time.Now().UTC()},
			},
		})
		if err == nil {
			t.Fatalf("非法序列号 %q 应拒绝签发", bad)
		}
		if !strings.Contains(err.Error(), "拒绝签发") {
			t.Fatalf("错误应说明拒绝签发原因, got: %v", err)
		}
	}
}

// TestGenerateWithOptions_NumberMonotonicity 锁定 M-4 修复:
// 显式编号必须为非负且大于已签发最大编号;自动路径在其后继续单调。
func TestGenerateWithOptions_NumberMonotonicity(t *testing.T) {
	auth := newHardeningAuth(t)
	gen := NewGenerator(auth, NewMemoryCRLCache())

	mk := func(n int) *GenerateOptions {
		return &GenerateOptions{Number: n}
	}

	// 负数拒绝。
	if _, err := gen.GenerateWithOptions(context.Background(), mk(-1)); err == nil {
		t.Fatal("负数 CRL number 应被拒绝")
	}
	// 首个显式编号 5 合法。
	if _, err := gen.GenerateWithOptions(context.Background(), mk(5)); err != nil {
		t.Fatalf("首个显式编号 5: %v", err)
	}
	// 回退编号拒绝(RFC 5280 §5.2.3 单调性)。
	if _, err := gen.GenerateWithOptions(context.Background(), mk(3)); err == nil {
		t.Fatal("编号回退(3 < 5)应被拒绝")
	}
	// 重复编号拒绝。
	if _, err := gen.GenerateWithOptions(context.Background(), mk(5)); err == nil {
		t.Fatal("重复编号 5 应被拒绝")
	}
	// 自动路径继续单调:应为 6。
	pem, err := gen.Generate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n, err := GetCRLNumber(pem)
	if err != nil {
		t.Fatal(err)
	}
	if n != 6 {
		t.Fatalf("自动编号应续接显式编号后为 6, got %d", n)
	}
}

// TestStartAutoUpdate_RejectsNonPositiveInterval 锁定 M-7 修复:
// 非正 interval 返回错误而非进入 ticker(ticker panic 位于子 goroutine
// 不可 recover,会崩溃整个进程)。
func TestStartAutoUpdate_RejectsNonPositiveInterval(t *testing.T) {
	auth := newHardeningAuth(t)
	single := NewGenerator(auth, NewMemoryCRLCache())
	if err := single.StartAutoUpdate(0); err == nil {
		t.Fatal("单实例 StartAutoUpdate(0) 应返回错误")
	}
	if err := single.StartAutoUpdate(-time.Minute); err == nil {
		t.Fatal("单实例 StartAutoUpdate(负值) 应返回错误")
	}

	fo := NewFanout(single, NewGenerator(auth, NewMemoryCRLCache()))
	if err := fo.StartAutoUpdate(0); err == nil {
		t.Fatal("fanout StartAutoUpdate(0) 应返回错误")
	}

	// 合法 interval 正常启动并停止(顺带覆盖构造期 stop 通道的启停路径)。
	s2 := NewGenerator(auth, NewMemoryCRLCache())
	if err := s2.StartAutoUpdate(time.Hour); err != nil {
		t.Fatalf("合法 interval: %v", err)
	}
	s2.StopAutoUpdate()
}
