package sm2_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/iuboy/pollux-go/sm2"
)

// TestCipherOrderRoundTripAllCombinations 对 (ASN.1, Plain) × (C1C3C2, C1C2C3) ×
// (uncompressed, compressed) 全组合做 Encrypt -> DecryptWithOpts 往返。
// Plain 路径覆盖压缩/未压缩点；ASN.1 路径忽略 compress（标准固定未压缩）。
func TestCipherOrderRoundTripAllCombinations(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("SM2 cipher order round-trip payload")

	cases := []struct {
		name     string
		encoding sm2.CipherEncoding
		order    sm2.CipherOrder
		compress bool
	}{
		{"ASN1_C1C3C2", sm2.EncodingASN1, sm2.OrderC1C3C2, false},
		// ASN1 + C1C2C3 不存在(ASN.1 字段序固定 C1C3C2),由
		// TestNewEncrypterOpts_RejectsASN1C1C2C3 断言显式报错。
		{"Plain_C1C3C2_uncomp", sm2.EncodingPlain, sm2.OrderC1C3C2, false},
		{"Plain_C1C2C3_uncomp", sm2.EncodingPlain, sm2.OrderC1C2C3, false},
		{"Plain_C1C3C2_comp", sm2.EncodingPlain, sm2.OrderC1C3C2, true},
		{"Plain_C1C2C3_comp", sm2.EncodingPlain, sm2.OrderC1C2C3, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encOpts, err := sm2.NewEncrypterOpts(tc.encoding, tc.order, tc.compress)
			if err != nil {
				t.Fatalf("NewEncrypterOpts: %v", err)
			}
			ct, err := sm2.Encrypt(rand.Reader, &key.PublicKey, msg, encOpts)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			decOpts, err := sm2.NewDecrypterOpts(tc.encoding, tc.order)
			if err != nil {
				t.Fatalf("NewDecrypterOpts: %v", err)
			}
			pt, err := sm2.DecryptWithOpts(key, ct, decOpts)
			if err != nil {
				t.Fatalf("DecryptWithOpts: %v", err)
			}
			if !bytes.Equal(pt, msg) {
				t.Errorf("round-trip mismatch: got %q, want %q", pt, msg)
			}
		})
	}
}

// TestDecrypt_LegacyC1C2C3_AdjustThenDecrypt 模拟收到遗留 C1C2C3 密文：
// 用 Plain+C1C2C3 加密 -> AdjustCipherOrder 转为国标 C1C3C2 -> 既有 Decrypt 解密。
// 这是与老系统互通的典型路径。
func TestDecrypt_LegacyC1C2C3_AdjustThenDecrypt(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("legacy C1C2C3 interop payload")

	// 1. 产出 legacy C1C2C3 Plain 密文
	encOpts, err := sm2.NewEncrypterOpts(sm2.EncodingPlain, sm2.OrderC1C2C3, false)
	if err != nil {
		t.Fatal(err)
	}
	ctLegacy, err := sm2.Encrypt(rand.Reader, &key.PublicKey, msg, encOpts)
	if err != nil {
		t.Fatal(err)
	}

	// 2. 直接用 Decrypt（默认 C1C3C2）应失败，证明顺序敏感
	if _, err := sm2.Decrypt(key, ctLegacy); err == nil {
		t.Fatal("Decrypt on C1C2C3 ciphertext should fail, but succeeded")
	}

	// 3. 调整顺序为 C1C3C2
	ctStd, err := sm2.AdjustCipherOrder(ctLegacy, sm2.OrderC1C2C3, sm2.OrderC1C3C2)
	if err != nil {
		t.Fatalf("AdjustCipherOrder: %v", err)
	}

	// 4. 用既有 Decrypt（自动探测 Plain，C1C3C2）应成功
	pt, err := sm2.Decrypt(key, ctStd)
	if err != nil {
		t.Fatalf("Decrypt after adjust: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Errorf("adjusted round-trip mismatch: got %q, want %q", pt, msg)
	}
}

// TestAdjustCipherOrder_RoundTrip 验证顺序转换两个方向可逆。
func TestAdjustCipherOrder_RoundTrip(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("adjust round-trip")

	// 起点：Plain + C1C3C2
	encOpts, err := sm2.NewEncrypterOpts(sm2.EncodingPlain, sm2.OrderC1C3C2, false)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sm2.Encrypt(rand.Reader, &key.PublicKey, msg, encOpts)
	if err != nil {
		t.Fatal(err)
	}

	// C1C3C2 -> C1C2C3 -> C1C3C2 应还原
	toLegacy, err := sm2.AdjustCipherOrder(ct, sm2.OrderC1C3C2, sm2.OrderC1C2C3)
	if err != nil {
		t.Fatal(err)
	}
	back, err := sm2.AdjustCipherOrder(toLegacy, sm2.OrderC1C2C3, sm2.OrderC1C3C2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, ct) {
		t.Error("adjust round-trip did not restore original ciphertext")
	}

	// 两种顺序的密文应解出相同明文（用各自对应 opts）
	ptStd, err := sm2.DecryptWithOpts(key, ct, mustDecOpts(t, sm2.EncodingPlain, sm2.OrderC1C3C2))
	if err != nil {
		t.Fatal(err)
	}
	ptLegacy, err := sm2.DecryptWithOpts(key, toLegacy, mustDecOpts(t, sm2.EncodingPlain, sm2.OrderC1C2C3))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ptStd, msg) || !bytes.Equal(ptLegacy, msg) {
		t.Error("both orderings must decrypt to the original message")
	}
}

// TestAdjustCipherOrder_NoOp 验证 from==to 为恒等（原切片直接返回）。
func TestAdjustCipherOrder_NoOp(t *testing.T) {
	ct := []byte{0x04, 0x01, 0x02, 0x03}
	out, err := sm2.AdjustCipherOrder(ct, sm2.OrderC1C3C2, sm2.OrderC1C3C2)
	if err != nil {
		t.Fatal(err)
	}
	if &out[0] != &ct[0] {
		t.Error("from==to should return the original slice (no copy)")
	}
}

// TestASN1PlainConversionRoundTrip 验证 ASN.1 <-> Plain 编码互转往返，
// 且转换前后密文均可用对应 opts 解出相同明文。
func TestASN1PlainConversionRoundTrip(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("asn1<->plain conversion")

	// 起点：ASN.1（国标默认）
	ctASN1, err := sm2.EncryptASN1(rand.Reader, &key.PublicKey, msg)
	if err != nil {
		t.Fatal(err)
	}

	// ASN.1 -> Plain（默认未压缩 + C1C3C2）
	toPlain, err := sm2.ASN1ToPlain(ctASN1, nil)
	if err != nil {
		t.Fatalf("ASN1ToPlain: %v", err)
	}
	// Plain 应可解
	ptFromPlain, err := sm2.DecryptWithOpts(key, toPlain, mustDecOpts(t, sm2.EncodingPlain, sm2.OrderC1C3C2))
	if err != nil {
		t.Fatalf("decrypt plain: %v", err)
	}
	if !bytes.Equal(ptFromPlain, msg) {
		t.Errorf("plain decrypt mismatch: got %q, want %q", ptFromPlain, msg)
	}

	// Plain -> ASN.1（输入是 C1C3C2）
	backASN1, err := sm2.PlainToASN1(toPlain, sm2.OrderC1C3C2)
	if err != nil {
		t.Fatalf("PlainToASN1: %v", err)
	}
	// 还原后应可被既有 Decrypt（ASN.1 + C1C3C2）解出
	ptBack, err := sm2.Decrypt(key, backASN1)
	if err != nil {
		t.Fatalf("decrypt back-to-ASN1: %v", err)
	}
	if !bytes.Equal(ptBack, msg) {
		t.Errorf("asn1 round-trip mismatch: got %q, want %q", ptBack, msg)
	}
}

// TestNewEncrypterOpts_InvalidOrder 验证未知 order 返回 error。
func TestNewEncrypterOpts_InvalidOrder(t *testing.T) {
	if _, err := sm2.NewEncrypterOpts(sm2.EncodingPlain, sm2.CipherOrder(99), false); err == nil {
		t.Error("expected error for invalid order")
	}
	if _, err := sm2.NewDecrypterOpts(sm2.EncodingPlain, sm2.CipherOrder(99)); err == nil {
		t.Error("expected error for invalid order")
	}
	if _, err := sm2.NewEncrypterOpts(sm2.CipherEncoding(99), sm2.OrderC1C3C2, false); err == nil {
		t.Error("expected error for invalid encoding")
	}
}

// TestEncrypt_NilOptsDefaultsToPlainC1C3C2 验证 opts=nil 时 Decrypt 仍可解
// （即 Encrypt nil-opts 产出的 Plain+C1C3C2 与 Decrypt 默认探测一致）。
func TestEncrypt_NilOptsDefaultsToPlainC1C3C2(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("nil opts default")
	ct, err := sm2.Encrypt(rand.Reader, &key.PublicKey, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := sm2.Decrypt(key, ct)
	if err != nil {
		t.Fatalf("Decrypt nil-opts ciphertext: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Errorf("mismatch: got %q, want %q", pt, msg)
	}
}

// TestEncrypt_NilPub 错误路径。
func TestEncrypt_NilPub(t *testing.T) {
	_, err := sm2.Encrypt(rand.Reader, nil, []byte("x"), nil)
	if err == nil {
		t.Error("expected error for nil public key")
	}
}

// TestDecryptWithOpts_NilPriv 错误路径。
func TestDecryptWithOpts_NilPriv(t *testing.T) {
	_, err := sm2.DecryptWithOpts(nil, []byte{0x30, 0x00}, nil)
	if err == nil {
		t.Error("expected error for nil private key")
	}
}

// mustDecOpts 是测试辅助：构造 DecrypterOpts，失败时 t.Fatal。
func mustDecOpts(t *testing.T, enc sm2.CipherEncoding, order sm2.CipherOrder) *sm2.DecrypterOpts {
	t.Helper()
	opts, err := sm2.NewDecrypterOpts(enc, order)
	if err != nil {
		t.Fatal(err)
	}
	return opts
}
