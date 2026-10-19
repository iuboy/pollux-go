package smx509

// 遗留项 C9 回归测试:传统 Proc-Type/DEK-Info PEM 的 DES 家族默认拒绝,
// 显式 opt-in(DecryptOptions.AllowLegacyDESPEM)后可解——合规姿态需要
// 能整体禁用弱密码而非静默接受一切传统密码。

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
)

// buildLegacyDESPEM 用包内同款 EVP_BytesToKey + DES-CBC 构造一个历史
// OpenSSL 风格的加密 PEM 块(RSA PRIVATE KEY + Proc-Type/DEK-Info 头)。
func buildLegacyDESPEM(t *testing.T, password string, plaintext []byte) []byte {
	t.Helper()
	iv := make([]byte, 8)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	key := evpBytesToKey([]byte(password), iv, 8)
	block, err := des.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	padLen := block.BlockSize() - len(plaintext)%block.BlockSize()
	padded := append(append([]byte(nil), plaintext...), bytes.Repeat([]byte{byte(padLen)}, padLen)...)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY",
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  fmt.Sprintf("DES-CBC,%s", hex.EncodeToString(iv)),
		},
		Bytes: ct,
	})
}

func TestDecryptPEMPrivateKey_DesRequiresOptIn(t *testing.T) {
	secret := append([]byte{0x30, 0x15}, []byte("legacy-des-payload")...) // 解密侧要求 ASN.1 SEQUENCE 开头
	encPEM := buildLegacyDESPEM(t, "historical-password", secret)

	// 默认策略:DES-CBC 拒绝(56 位死密码,合规姿态需要显式 opt-in)。
	_, err := DecryptPEMPrivateKey(encPEM, "historical-password")
	if !errors.Is(err, errLegacyDESRequiresOptIn) {
		t.Fatalf("默认策略应拒绝 DES-CBC: %v", err)
	}
	_, err = DecryptPEMPrivateKeyDER(encPEM, "historical-password")
	if !errors.Is(err, errLegacyDESRequiresOptIn) {
		t.Fatalf("DER 变体默认策略应拒绝 DES-CBC: %v", err)
	}

	// opt-in 后可解,内容往返一致。
	der, err := DecryptPEMPrivateKeyDERWithOptions(encPEM, "historical-password", DecryptOptions{AllowLegacyDESPEM: true})
	if err != nil {
		t.Fatalf("opt-in 后应可解: %v", err)
	}
	if !bytes.Contains(der, secret) {
		t.Fatal("解密结果应含原始明文")
	}

	// 错误口令在 opt-in 下走正常解密失败路径(而非策略拒绝)。
	if _, err := DecryptPEMPrivateKeyDERWithOptions(encPEM, "wrong", DecryptOptions{AllowLegacyDESPEM: true}); err == nil {
		t.Fatal("错误口令应解密失败")
	}
}
