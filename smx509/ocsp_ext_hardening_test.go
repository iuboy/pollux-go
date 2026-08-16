package smx509

// 安全加固回归测试(第二轮审查 M1/M3/M4 修复)。

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/sm2"
	"golang.org/x/crypto/ocsp"
)

// TestCreateOCSPResponseExt_RejectsSM2CurveECDSAKey 锁定 M1:SM2 曲线上的
// *ecdsa.PrivateKey 按包内约定是 SM2 密钥,静默用普通 ECDSA-SHA256 签名
// 属算法降级(GM 合规失败/依赖方 OID 白名单全拒),必须显式报错。
func TestCreateOCSPResponseExt_RejectsSM2CurveECDSAKey(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !IsSM2PublicKey(&ecPriv.PublicKey) {
		t.Fatal("前置条件:密钥应在 SM2 曲线上")
	}
	_, err = CreateOCSPResponseExt(nil, nil, &OCSPResponseParams{Nonce: nil}, ecPriv)
	if err == nil {
		t.Fatal("SM2 曲线的 *ecdsa.PrivateKey 应被显式拒绝")
	}
}

// TestCreateOCSPResponseExt_NonceMinimumLength 锁定 M4:< 16 字节的 nonce
// 绑定强度不足(RFC 8954 §2.3),构造侧拒绝。
func TestCreateOCSPResponseExt_NonceMinimumLength(t *testing.T) {
	key, _ := sm2.GenerateKey(rand.Reader)
	cert := makeResponderKey(t, key)
	now := time.Now().UTC()

	_, err := CreateOCSPResponseExt(cert, cert, &OCSPResponseParams{
		Status: ocsp.Good, SerialNumber: big.NewInt(1),
		ThisUpdate: now, NextUpdate: now.Add(time.Hour),
		Nonce: []byte("short"),
	}, key)
	if err == nil {
		t.Fatal("短 nonce 应被拒绝")
	}
}

// TestVerifyOCSPResponseNonce 锁定 M3:客户端发出 nonce 后,响应缺失 nonce
// (剥离重放攻击面)或回显不匹配都必须拒绝。
func TestVerifyOCSPResponseNonce(t *testing.T) {
	key, _ := sm2.GenerateKey(rand.Reader)
	cert := makeResponderKey(t, key)
	now := time.Now().UTC()
	sent := []byte("client-nonce-0123456") // 19 bytes

	build := func(nonce []byte) []byte {
		t.Helper()
		der, err := CreateOCSPResponseExt(cert, cert, &OCSPResponseParams{
			Status: ocsp.Good, SerialNumber: big.NewInt(2),
			ThisUpdate: now, NextUpdate: now.Add(time.Hour),
			Nonce: nonce,
		}, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}

	// 匹配:通过。
	if err := VerifyOCSPResponseNonce(build(sent), sent); err != nil {
		t.Fatalf("匹配 nonce 应通过: %v", err)
	}
	// 不匹配:拒绝。
	other := []byte("client-nonce-9876543")
	if err := VerifyOCSPResponseNonce(build(other), sent); err == nil {
		t.Fatal("nonce 不匹配应拒绝")
	}
	// 响应无 nonce 而请求发了:拒绝(经典剥离重放面)。
	if err := VerifyOCSPResponseNonce(build(nil), sent); err == nil {
		t.Fatal("请求发了 nonce 而响应缺失必须拒绝")
	}
	// 未发送 nonce:无操作。
	if err := VerifyOCSPResponseNonce(build(sent), nil); err != nil {
		t.Fatalf("未发送 nonce 应为无操作: %v", err)
	}
	// 发送的 nonce 过短:拒绝。
	if err := VerifyOCSPResponseNonce(build(sent), []byte("tiny")); err == nil {
		t.Fatal("过短的 sent nonce 应拒绝")
	}
}
