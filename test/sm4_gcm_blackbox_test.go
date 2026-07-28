// 这些测试覆盖 sm4 包的 SM4-GCM 高级 API（合并自原 sm4gcm 包）：
// NewGCM / GenerateNonce / SealRandomNonce / OpenWithNonce / ZeroKey / ZeroNonce。
//
// 历史上这些能力由独立的 sm4gcm 包提供；现已合并到 sm4 包（见 sm4/gcm.go），
// 因为 sm4gcm 与 sm4 的核心密码学完全等价（sm4gcm 仅是 sm4.NewCipher +
// cipher.NewGCM 的薄封装），且 sm4.Encrypt 的 ModeGCM 分支已支持随机 nonce。

package test

import (
	"bytes"
	"crypto/cipher"
	"testing"

	polluxSM4 "github.com/iuboy/pollux-go/sm4"
)

// newSM4GCM 构造一个 SM4-GCM AEAD，验证 sm4.NewGCM。
func newSM4GCM(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	aead, err := polluxSM4.NewGCM(key)
	if err != nil {
		t.Fatalf("sm4.NewGCM: %v", err)
	}
	return aead
}

func generateSM4Key(t *testing.T) []byte {
	t.Helper()
	key, err := polluxSM4.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

func TestBlackBox_SM4GCM_GenerateKey_Size(t *testing.T) {
	key, err := polluxSM4.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(key) != polluxSM4.KeySize {
		t.Errorf("key length: got %d, want %d", len(key), polluxSM4.KeySize)
	}
}

func TestBlackBox_SM4GCM_GenerateKey_Unique(t *testing.T) {
	k1, _ := polluxSM4.GenerateKey()
	k2, _ := polluxSM4.GenerateKey()
	if bytes.Equal(k1, k2) {
		t.Error("two generated keys should differ")
	}
}

func TestBlackBox_SM4GCM_GenerateNonce_Size(t *testing.T) {
	nonce, err := polluxSM4.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	if len(nonce) != polluxSM4.GCMNonceSize {
		t.Errorf("nonce length: got %d, want %d", len(nonce), polluxSM4.GCMNonceSize)
	}
}

func TestBlackBox_SM4GCM_GenerateNonce_Unique(t *testing.T) {
	n1, _ := polluxSM4.GenerateNonce()
	n2, _ := polluxSM4.GenerateNonce()
	if bytes.Equal(n1, n2) {
		t.Error("two generated nonces should differ")
	}
}

func TestBlackBox_SM4GCM_SealOpen_RoundTrip(t *testing.T) {
	key := generateSM4Key(t)
	nonce, _ := polluxSM4.GenerateNonce()
	plaintext := []byte("SM4-GCM black-box round trip test")
	aad := []byte("additional-data")

	aead := newSM4GCM(t, key)
	ct := aead.Seal(nil, nonce, plaintext, aad)

	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("roundtrip: got %q, want %q", pt, plaintext)
	}
}

func TestBlackBox_SM4GCM_Open_WrongKey(t *testing.T) {
	key := generateSM4Key(t)
	wrongKey := generateSM4Key(t)
	nonce, _ := polluxSM4.GenerateNonce()

	aead := newSM4GCM(t, key)
	ct := aead.Seal(nil, nonce, []byte("secret"), nil)

	wrongAEAD := newSM4GCM(t, wrongKey)
	_, err := wrongAEAD.Open(nil, nonce, ct, nil)
	if err == nil {
		t.Error("Open with wrong key should fail")
	}
}

func TestBlackBox_SM4GCM_Open_AADTamperRejected(t *testing.T) {
	key := generateSM4Key(t)
	nonce, _ := polluxSM4.GenerateNonce()

	aead := newSM4GCM(t, key)
	ct := aead.Seal(nil, nonce, []byte("data"), []byte("aad-original"))
	_, err := aead.Open(nil, nonce, ct, []byte("aad-tampered"))
	if err == nil {
		t.Error("Open with tampered AAD should fail")
	}
}

func TestBlackBox_SM4GCM_Open_TagTamperRejected(t *testing.T) {
	key := generateSM4Key(t)
	nonce, _ := polluxSM4.GenerateNonce()

	aead := newSM4GCM(t, key)
	ct := aead.Seal(nil, nonce, []byte("data"), nil)
	ct[len(ct)-1] ^= 0xff
	_, err := aead.Open(nil, nonce, ct, nil)
	if err == nil {
		t.Error("Open with tampered tag should fail")
	}
}

func TestBlackBox_SM4GCM_NewGCM_InvalidKeySize(t *testing.T) {
	// sm4.NewGCM 内部 sm4.NewCipher 对非 16 字节密钥返回错误。
	if _, err := polluxSM4.NewGCM([]byte("short")); err == nil {
		t.Error("NewGCM with wrong key size should fail")
	}
}

// TestBlackBox_SM4GCM_SealRandomNonce 验证合并后的 sm4.SealRandomNonce：
// 一次性生成随机 nonce + 密文，并通过 OpenWithNonce 往返。
func TestBlackBox_SM4GCM_SealRandomNonce(t *testing.T) {
	key := generateSM4Key(t)
	plaintext := []byte("auto-nonce test via sm4.SealRandomNonce")
	aad := []byte("aad")

	sealed, err := polluxSM4.SealRandomNonce(key, plaintext, aad)
	if err != nil {
		t.Fatalf("SealRandomNonce: %v", err)
	}
	if len(sealed.Nonce) != polluxSM4.GCMNonceSize {
		t.Errorf("nonce length: got %d, want %d", len(sealed.Nonce), polluxSM4.GCMNonceSize)
	}
	if len(sealed.Ciphertext) == 0 {
		t.Error("ciphertext should not be empty")
	}

	pt, err := polluxSM4.OpenWithNonce(key, sealed, aad)
	if err != nil {
		t.Fatalf("OpenWithNonce: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("roundtrip: got %q, want %q", pt, plaintext)
	}
}

// TestBlackBox_SM4GCM_SealRandomNonce_NoncesUnique 验证 SealRandomNonce
// 每次生成的 nonce 都不同（防 nonce 重用）。
func TestBlackBox_SM4GCM_SealRandomNonce_NoncesUnique(t *testing.T) {
	key := generateSM4Key(t)
	s1, _ := polluxSM4.SealRandomNonce(key, []byte("a"), nil)
	s2, _ := polluxSM4.SealRandomNonce(key, []byte("b"), nil)
	if bytes.Equal(s1.Nonce, s2.Nonce) {
		t.Error("SealRandomNonce produced duplicate nonces")
	}
}

// TestBlackBox_SM4GCM_ZeroKey_ZeroNonce 验证便捷清零函数确实把切片清零。
func TestBlackBox_SM4GCM_ZeroKey_ZeroNonce(t *testing.T) {
	key := generateSM4Key(t)
	nonce, _ := polluxSM4.GenerateNonce()

	polluxSM4.ZeroKey(key)
	polluxSM4.ZeroNonce(nonce)

	for i, b := range key {
		if b != 0 {
			t.Errorf("key byte at %d not zeroed: 0x%02x", i, b)
		}
	}
	for i, b := range nonce {
		if b != 0 {
			t.Errorf("nonce byte at %d not zeroed: 0x%02x", i, b)
		}
	}
}
