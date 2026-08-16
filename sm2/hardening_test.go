package sm2_test

// 安全加固回归测试(第二轮审查 M-1/M-2/M-3 与 NewPrivateKeyFromInt 修复)。

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/iuboy/pollux-go/sm2"
)

// TestNewPrivateKeyFromInt_Domain 锁定标量域校验:越界 panic 转错误、
// 负数/零拒绝(历史实现负数被静默取绝对值)。
func TestNewPrivateKeyFromInt_Domain(t *testing.T) {
	n := sm2.P256().Params().N

	if _, err := sm2.NewPrivateKeyFromInt(nil); err == nil {
		t.Fatal("nil scalar 应被拒绝")
	}
	if _, err := sm2.NewPrivateKeyFromInt(big.NewInt(0)); err == nil {
		t.Fatal("零标量应被拒绝")
	}
	if _, err := sm2.NewPrivateKeyFromInt(big.NewInt(-1)); err == nil {
		t.Fatal("负标量应被拒绝(不得静默取绝对值)")
	}
	// >= n 拒绝(历史实现对 >= 2^256 直接 panic)。
	if _, err := sm2.NewPrivateKeyFromInt(new(big.Int).Set(n)); err == nil {
		t.Fatal("标量 == n 应被拒绝")
	}
	over := new(big.Int).Lsh(big.NewInt(1), 260)
	if _, err := sm2.NewPrivateKeyFromInt(over); err == nil {
		t.Fatal("超大标量应返回错误而非 panic")
	}

	// 合法域 [1, n-1] 正常。
	k, err := sm2.NewPrivateKeyFromInt(big.NewInt(1))
	if err != nil {
		t.Fatalf("合法标量 1: %v", err)
	}
	if k.D.Cmp(big.NewInt(1)) != 0 {
		t.Fatal("D 应等于输入标量")
	}
}

// TestNewEncrypterOpts_RejectsASN1C1C2C3 锁定 M-3:该组合不存在,
// 必须显式报错而非静默产出 C1C3C2。
func TestNewEncrypterOpts_RejectsASN1C1C2C3(t *testing.T) {
	_, err := sm2.NewEncrypterOpts(sm2.EncodingASN1, sm2.OrderC1C2C3, false)
	if err == nil {
		t.Fatal("EncodingASN1 + OrderC1C2C3 应显式报错")
	}
	if !strings.Contains(err.Error(), "C1C3C2") {
		t.Fatalf("错误应说明 ASN.1 固定序: %v", err)
	}
}

// TestAdjustCipherOrder_RejectsASN1Input 锁定 M-1:ASN.1 输入的顺序转换
// 显式报错(历史实现静默输出 Plain 编码,下游期望 ASN.1 即错位)。
func TestAdjustCipherOrder_RejectsASN1Input(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := sm2.NewEncrypterOpts(sm2.EncodingASN1, sm2.OrderC1C3C2, false)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sm2.Encrypt(rand.Reader, &key.PublicKey, []byte("payload"), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) == 0 || ct[0] != 0x30 {
		t.Fatalf("前置条件:应得到 ASN.1 密文(0x30 前缀), got %v", ct[:1])
	}

	_, err = sm2.AdjustCipherOrder(ct, sm2.OrderC1C3C2, sm2.OrderC1C2C3)
	if err == nil {
		t.Fatal("对 ASN.1 密文做顺序转换应显式报错")
	}
}

// TestPlainToASN1_RejectsCompressedPoint 锁定 M-2:压缩点输入显式报错
// (历史实现静默产出损坏的 ASN.1)。
func TestPlainToASN1_RejectsCompressedPoint(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := sm2.NewEncrypterOpts(sm2.EncodingPlain, sm2.OrderC1C3C2, true)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sm2.Encrypt(rand.Reader, &key.PublicKey, []byte("payload"), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) == 0 || (ct[0] != 0x02 && ct[0] != 0x03) {
		t.Fatalf("前置条件:应得到压缩点密文, got prefix %v", ct[:1])
	}

	_, err = sm2.PlainToASN1(ct, sm2.OrderC1C3C2)
	if err == nil {
		t.Fatal("压缩点 Plain 密文转 ASN.1 应显式报错")
	}
}

// TestEnvelopeDecrypt_FailureOpaque 锁定脱敏回归(I7):EnvelopeDecrypt 的
// 各失败路径必须统一返回 errDecryptFailed(可 errors.Is),不泄露失败分层
// (SM2 解封装 vs 对称解密)——错误消息 oracle 的必要条件已封死。
func TestEnvelopeDecrypt_FailureOpaque(t *testing.T) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// 正常加密得到合法 envelope(certDER 由 EnvelopeEncrypt 填充)。
	env, err := sm2.EnvelopeEncrypt(&priv.PublicKey, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	// 篡改 EnvelopedData(公有字段):解密必须失败且错误为 ErrDecryptFailed。
	env.EnvelopedData[3] ^= 0xFF
	_, err = sm2.EnvelopeDecrypt(priv, env)
	if err == nil || !errors.Is(err, sm2.ErrDecryptFailed) {
		t.Fatalf("篡改 EnvelopedData 应返回 ErrDecryptFailed, got: %v", err)
	}

	// 结构彻底损坏的 EnvelopedData:同样落 opaque 错误。
	env2, _ := sm2.EnvelopeEncrypt(&priv.PublicKey, []byte("secret2"))
	env2.EnvelopedData = []byte{0x30, 0x03, 0x02, 0x01}
	_, err = sm2.EnvelopeDecrypt(priv, env2)
	if err == nil || !errors.Is(err, sm2.ErrDecryptFailed) {
		t.Fatalf("损坏结构应返回 ErrDecryptFailed, got: %v", err)
	}
}
