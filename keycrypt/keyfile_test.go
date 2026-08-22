package keycrypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/iuboy/pollux-go/sm2"
)

const testPassword = "correct-horse-battery-staple-123"

// newTestSigner 生成指定算法的测试私钥。
func newTestSigner(t *testing.T, algo string) crypto.Signer {
	t.Helper()
	switch algo {
	case "rsa-2048":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("RSA 生成失败: %v", err)
		}
		return k
	case "ecdsa-p256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ECDSA P-256 生成失败: %v", err)
		}
		return k
	case "ecdsa-p384":
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("ECDSA P-384 生成失败: %v", err)
		}
		return k
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Ed25519 生成失败: %v", err)
		}
		return priv
	case "sm2":
		// sm2.GenerateKey 生成 SM2 私钥（*sm2.PrivateKey 实现 crypto.Signer）
		k, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("SM2 生成失败: %v", err)
		}
		return k
	default:
		t.Fatalf("未知算法: %s", algo)
		return nil
	}
}

// TestMarshalLoadEncryptedPrivateKey_RoundTrip 全算法加密→加载往返。
func TestMarshalLoadEncryptedPrivateKey_RoundTrip(t *testing.T) {
	t.Parallel()
	algos := []string{"rsa-2048", "ecdsa-p256", "ecdsa-p384", "ed25519", "sm2"}
	for _, algo := range algos {

		t.Run(algo, func(t *testing.T) {
			t.Parallel()
			key := newTestSigner(t, algo)

			// 加密
			pemBytes, err := MarshalEncryptedPrivateKey(key, testPassword)
			if err != nil {
				t.Fatalf("MarshalEncryptedPrivateKey 失败: %v", err)
			}
			// 验证是 ENCRYPTED PRIVATE KEY PEM
			if string(pemBytes[:27]) != "-----BEGIN ENCRYPTED PRIVAT" {
				t.Errorf("PEM 头不是 ENCRYPTED PRIVATE KEY: %q", string(pemBytes[:40]))
			}

			// 加载
			der, err := LoadEncryptedPrivateKey(pemBytes, testPassword)
			if err != nil {
				t.Fatalf("LoadEncryptedPrivateKey 失败: %v", err)
			}
			if len(der) == 0 {
				t.Fatal("解密后的 DER 为空")
			}
		})
	}
}

// TestMarshalEncryptedPrivateKey_WrongPassword 错误密码应解密失败。
func TestMarshalEncryptedPrivateKey_WrongPassword(t *testing.T) {
	t.Parallel()
	key := newTestSigner(t, "ecdsa-p256")
	pemBytes, err := MarshalEncryptedPrivateKey(key, testPassword)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	_, err = LoadEncryptedPrivateKey(pemBytes, "wrong-password")
	if err == nil {
		t.Fatal("错误密码应解密失败，实际成功")
	}
}

// TestMarshalEncryptedPrivateKey_EmptyPassword 空密码应拒绝（破坏性策略）。
func TestMarshalEncryptedPrivateKey_EmptyPassword(t *testing.T) {
	t.Parallel()
	key := newTestSigner(t, "ecdsa-p256")
	_, err := MarshalEncryptedPrivateKey(key, "")
	if !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("空密码应返回 ErrPasswordRequired，实际: %v", err)
	}
}

// TestLoadEncryptedPrivateKey_EmptyPassword 加载时空密码应拒绝。
func TestLoadEncryptedPrivateKey_EmptyPassword(t *testing.T) {
	t.Parallel()
	_, err := LoadEncryptedPrivateKey([]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\n-----END ENCRYPTED PRIVATE KEY-----"), "")
	if !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("空密码应返回 ErrPasswordRequired，实际: %v", err)
	}
}

// TestLoadEncryptedPrivateKey_PlaintextRejected 明文 PEM 应拒绝（破坏性）。
func TestLoadEncryptedPrivateKey_PlaintextRejected(t *testing.T) {
	t.Parallel()
	key := newTestSigner(t, "ecdsa-p256")
	// 生成标准明文 PKCS#8 PEM（攻击/误配场景）
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8 失败: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	_, err = LoadEncryptedPrivateKey(pemBytes, testPassword)
	if !errors.Is(err, ErrPlaintextKeyRejected) {
		t.Fatalf("明文 PEM 应返回 ErrPlaintextKeyRejected，实际: %v", err)
	}
}

// TestLoadEncryptedPrivateKey_InvalidPEM 无效 PEM 应错误。
func TestLoadEncryptedPrivateKey_InvalidPEM(t *testing.T) {
	t.Parallel()
	_, err := LoadEncryptedPrivateKey([]byte("not a pem"), testPassword)
	if err == nil {
		t.Fatal("无效 PEM 应返回错误")
	}
}

// TestMarshalEncryptedPrivateKey_DifferentPasswordsDifferentPEM
// 相同密钥不同密码应生成不同密文（验证密码确实影响密文）。
func TestMarshalEncryptedPrivateKey_DifferentPasswordsDifferentPEM(t *testing.T) {
	t.Parallel()
	key := newTestSigner(t, "ecdsa-p256")
	pem1, _ := MarshalEncryptedPrivateKey(key, "password-one")
	pem2, _ := MarshalEncryptedPrivateKey(key, "password-two")
	if string(pem1) == string(pem2) {
		t.Error("不同密码应生成不同密文")
	}
}

// TestMarshalEncryptedPrivateKey_SamePasswordNonDeterministic
// 相同密钥相同密码两次加密应生成不同密文（随机 salt/IV）。
func TestMarshalEncryptedPrivateKey_SamePasswordNonDeterministic(t *testing.T) {
	t.Parallel()
	key := newTestSigner(t, "ecdsa-p256")
	pem1, _ := MarshalEncryptedPrivateKey(key, testPassword)
	pem2, _ := MarshalEncryptedPrivateKey(key, testPassword)
	if string(pem1) == string(pem2) {
		t.Error("相同密钥密码应生成不同密文（随机 salt/IV），实际相同")
	}
}
